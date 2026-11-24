package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/term"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(os.Stderr, "Usage: cc-controlplane <init|admin-add|migrate-sqlite|serve> [flags]")
		return nil
	}
	cmd := args[0]
	flags := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dsn := flags.String("db", os.Getenv("DATABASE_URL"), "PostgreSQL URL (defaults to DATABASE_URL)")
	var settingsPath, adminName, listen, certFile, keyFile string
	var port int
	var trusted []string
	switch cmd {
	case "init":
		flags.StringVar(&settingsPath, "settings", "", "JSON settings file")
		flags.StringVar(&adminName, "admin", "", "create the named administrator and print its generated password")
	case "admin-add", "migrate-sqlite":
	case "serve":
		flags.StringVar(&listen, "listen", "127.0.0.1", "listen address")
		flags.IntVar(&port, "port", 8443, "listen port")
		flags.StringVar(&certFile, "tls-cert", "", "TLS certificate file")
		flags.StringVar(&keyFile, "tls-key", "", "TLS private key file")
		flags.Func("trusted-proxy", "trusted reverse proxy address or CIDR, repeatable", func(value string) error {
			trusted = append(trusted, value)
			return nil
		})
	default:
		return fmt.Errorf("unknown command %q; use init, admin-add, migrate-sqlite or serve", cmd)
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if cmd == "admin-add" && flags.NArg() != 1 {
		return errors.New("usage: cc-controlplane admin-add [--db URL] NAME")
	}
	if cmd == "migrate-sqlite" && flags.NArg() != 1 {
		return errors.New("usage: cc-controlplane migrate-sqlite [--db URL] SOURCE.db")
	}
	if cmd != "admin-add" && cmd != "migrate-sqlite" && flags.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments", cmd)
	}
	if *dsn == "" {
		return errors.New("set DATABASE_URL or pass --db with a PostgreSQL connection string")
	}
	if (certFile == "") != (keyFile == "") {
		return errors.New("--tls-cert and --tls-key must be supplied together")
	}

	openCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s, err := openStore(openCtx, *dsn)
	if err != nil {
		return err
	}
	defer s.pool.Close()
	switch cmd {
	case "init":
		return initialize(ctx, s, settingsPath, adminName)
	case "migrate-sqlite":
		return s.migrateSQLite(ctx, flags.Arg(0))
	case "admin-add":
		name := flags.Arg(0)
		password := os.Getenv("CP_ADMIN_PASSWORD")
		if password == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("set CP_ADMIN_PASSWORD or run admin-add in a terminal")
			}
			fmt.Fprintf(os.Stderr, "Password for %s: ", name)
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
			password = string(raw)
		}
		if err := s.addAdmin(ctx, name, password); err != nil {
			return err
		}
		fmt.Printf("console admin %s created\n", name)
		return nil
	}
	trusted = append(trusted, strings.Split(os.Getenv("CP_TRUSTED_PROXIES"), ",")...)
	return serve(ctx, s, net.JoinHostPort(listen, strconv.Itoa(port)), certFile, keyFile, trusted)
}

func initialize(ctx context.Context, s *store, path, name string) error {
	var body fields
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &body); err != nil || body == nil {
			return errors.New("settings file must contain a JSON object")
		}
	}
	values, err := settingsPatch(body)
	if err != nil {
		return err
	}
	var password, hashed string
	if name != "" {
		password = randomToken(12)
		hashed, err = prepareAdmin(name, password)
		if err != nil {
			return err
		}
	}
	err = s.mutate(ctx, func(tx pgx.Tx) error {
		if err := setSettings(ctx, tx, values); err != nil {
			return err
		}
		if name != "" {
			return insertAdmin(ctx, tx, name, hashed, s.now())
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Println("initialized PostgreSQL control plane")
	if name != "" {
		fmt.Printf("console admin %s, password %s (shown once)\n", name, password)
	}
	return nil
}

func serve(ctx context.Context, s *store, address, cert, key string, trusted []string) error {
	admin := os.Getenv("CP_ADMIN_TOKEN")
	if admin == "" {
		var hasAdmin bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM admins)").Scan(&hasAdmin); err != nil {
			return err
		}
		if !hasAdmin {
			return errors.New("set CP_ADMIN_TOKEN or create an administrator with cc-controlplane admin-add")
		}
	}
	proxies, err := parseProxies(trusted)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	httpd := &http.Server{
		Handler: newAPI(s, admin, os.Getenv("CP_PROBE_TOKEN"), proxies), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 20 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runAlerts(workerCtx)
	}()
	billingDone := make(chan struct{})
	go func() {
		defer close(billingDone)
		s.runSubscriptionExpiry(workerCtx)
	}()
	defer func() {
		cancel()
		<-done
		<-billingDone
	}()

	fmt.Printf("control plane listening on %s\n", listener.Addr())
	errs := make(chan error, 1)
	go func() {
		if cert != "" {
			errs <- httpd.ServeTLS(listener, cert, key)
		} else {
			errs <- httpd.Serve(listener)
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := httpd.Shutdown(shutdown); err != nil {
			httpd.Close()
			return err
		}
		return nil
	}
}
