// Command ccproxy-exit-agent keeps an exit node's sing-box in step with the aifree control plane.
//
// It is the compiled counterpart of controlplane/agent.py (which stays available to existing callers) and speaks
// the same agent API and heartbeat contract:
//
//   - GET /agent/ips; with --iface (Linux only) every address is added to the interface as a /32.
//   - GET /agent/server-config with If-None-Match. A new version waits until none newer has arrived for --settle
//     seconds (at most --max-delay), is checked with `sing-box check`, staged in --state-dir and copied to --config
//     only for a reload. A version that fails the check is not retried.
//   - Each candidate gets a random Clash API secret and a marker outbound. After a reload the agent asks sing-box on
//     --confirm-api (loopback) for /proxies with that secret; only an answer that lists the marker confirms the
//     candidate. The heartbeat (POST /agent/report) carries config_etag (the confirmed version), apply_state
//     (confirmed / pending / failed / unknown), apply_error, candidate_etag, singbox_running and egress probes.
//   - When a reload fails definitively the last confirmed configuration is put back at --config.
//   - Every --probe-interval seconds each URL from /agent/probe-targets is fetched from every egress IP, bound to
//     that IP, in the background; results go out with the next heartbeats.
//   - XTCP hosts (xtcp.go, with --frpc-config): GET /agent/xtcp, the host's desired frpc proxies. A new generation is
//     verified, written, hot-reloaded (or frpc restarted with --frpc-restart-cmd when its frps settings changed),
//     and confirmed only once frpc's loopback admin API lists every proxy as registered; otherwise the working
//     configuration is restored. The heartbeat carries the outcome in "xtcp".
//   - Per-device traffic (usage.go): each candidate also gets sing-box's API service on --usage-api (loopback,
//     sing-box 1.14+). The agent follows its connection events and sends upload and download bytes per VLESS user
//     and UTC hour to POST /agent/usage every --usage-interval seconds, independently of sync and heartbeats.
//     --usage-api off, or a sing-box without the API service, leaves usage reported as unavailable.
//
// Reload, one of:
//
//	--run          supervise sing-box as a child: SIGHUP on Unix; on Windows (no SIGHUP) stop it and start it
//	               again on the new file (--run-reload restart). Either way the version counts only once confirmed.
//	--reload-cmd   run a command, e.g. "systemctl reload-or-restart ccproxy-exit-singbox"
//
// The token comes from --token-file (first line; a root/SYSTEM-only file written by the installer) or from
// CP_AGENT_TOKEN. Requests to the control plane never follow redirects, so the token only goes to --cp.
//
// Other subcommands:
//
//	ccproxy-exit-agent version
//	ccproxy-exit-agent check-args ARGS...          exit 0 when this binary accepts ARGS as its command line (the
//	                                               updater runs a candidate with the running agent's arguments)
//	ccproxy-exit-agent ips up|down IFACE FILE      Linux: add the addresses in FILE to IFACE (boot unit), or
//	                                               remove the ones this agent added (recorded in owned-ips.txt)
//
// Managed updates (update.go, docs/exit-agent-updates.md): the agent polls GET /agent/update, verifies the signed
// release record against the keys compiled in from release_keys.txt, downloads and self-tests the candidate in the
// background into <bin>/releases/<version>/, and exits with status 75. The binary the service runs is a stable
// launcher (launcher.go) that is never replaced by an update: it starts the candidate, counts its starts, and rolls
// it back to the previous release when it does not report healthy. The heartbeat carries agent_version and the
// update state.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println("ccproxy-exit-agent", version)
			return
		case "ips":
			os.Exit(ipsCommand(os.Args[2:]))
		case "check-args":
			os.Exit(checkArgs(os.Args[2:]))
		}
	}
	// The stable launcher (launcher.go) picks the release to run; it returns here to run this binary itself.
	if code, here := launch(os.Args[1:]); !here {
		os.Exit(code)
	}
	os.Exit(run(os.Args[1:]))
}

func ipsCommand(args []string) int {
	if len(args) != 3 || (args[0] != "up" && args[0] != "down") {
		fmt.Fprintln(os.Stderr, "usage: ccproxy-exit-agent ips up|down IFACE FILE")
		return 2
	}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	change := ipsUp
	if args[0] == "down" {
		change = ipsDown
	}
	if err := change(args[1], args[2], logf); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func readToken(path string) (string, error) {
	if path == "" {
		return strings.TrimSpace(os.Getenv("CP_AGENT_TOKEN")), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line), nil
}

// cliOptions is the parsed command line.
type cliOptions struct {
	Options
	tokenFile, logFile string
}

// parseArgs parses and checks the agent's command line without side effects (run and check-args).
func parseArgs(argv []string, stderr io.Writer) (cliOptions, error) {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("ccproxy-exit-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c cliOptions
	o := &c.Options
	var ipsScript string
	fs.StringVar(&o.CP, "cp", "", "control plane base URL (https)")
	fs.StringVar(&o.CAFile, "cafile", "", "CA bundle for a private control-plane certificate")
	fs.StringVar(&c.tokenFile, "token-file", "", "read the agent token from this file instead of CP_AGENT_TOKEN")
	fs.StringVar(&o.Iface, "iface", "", "Linux: interface for the egress IPs; omit to skip IP management")
	fs.StringVar(&ipsScript, "ips-script", "", "accepted for agent.py compatibility; the IPs are managed natively")
	fs.StringVar(&o.Config, "config", "/etc/sing-box/config.json", "the sing-box config file sing-box runs")
	fs.StringVar(&o.StateDir, "state-dir", "/var/lib/egress-agent", "directory for candidate/confirmed copies and state")
	fs.StringVar(&o.SingBox, "singbox", "sing-box", "sing-box executable (for check, and run with --run)")
	fs.Float64Var(&o.Interval, "interval", 5, "seconds between sync cycles")
	fs.Float64Var(&o.Settle, "settle", 10, "install a new version only after this many seconds without a newer one")
	fs.Float64Var(&o.MaxDelay, "max-delay", 60, "install anyway once a pending version has waited this long")
	fs.StringVar(&o.Name, "name", host, "agent name shown in logs and reports")
	fs.Float64Var(&o.ProbeInterval, "probe-interval", 60, "seconds between egress probe rounds")
	fs.Float64Var(&o.ProbeTimeout, "probe-timeout", 10, "seconds per egress probe")
	fs.StringVar(&o.StatusCmd, "status-cmd", "", "with --reload-cmd: exits 0 when sing-box is up (reported only)")
	fs.StringVar(&o.ConfirmAPI, "confirm-api", "127.0.0.1:9095", "numeric loopback address:port for the confirmation API")
	fs.StringVar(&o.UsageAPI, "usage-api", "127.0.0.1:9096", "numeric loopback address:port for sing-box's API service (per-device traffic), or off")
	fs.Float64Var(&o.UsageInterval, "usage-interval", 60, "seconds between usage reports (10-600)")
	fs.Float64Var(&o.ConfirmTimeout, "confirm-timeout", 15, "seconds to wait for sing-box to confirm a reloaded config")
	fs.BoolVar(&o.Once, "once", false, "sync once and exit")
	fs.BoolVar(&o.Run, "run", false, "supervise sing-box as a child process")
	fs.StringVar(&o.ReloadCmd, "reload-cmd", "", "command that makes sing-box load --config")
	fs.StringVar(&o.RunReload, "run-reload", "", "with --run: signal (SIGHUP) or restart; default signal, restart on Windows")
	fs.StringVar(&o.FrpcConfig, "frpc-config", "", "XTCP hosts: the frpc.toml frpc runs; enables XTCP mapping sync")
	fs.StringVar(&o.FrpcBin, "frpc", "frpc", "with --frpc-config: frpc executable (for verify)")
	fs.StringVar(&o.FrpcCA, "frpc-ca", "", "with --frpc-config: the CA file frpc.toml names for frps")
	fs.StringVar(&o.FrpcLog, "frpc-log", "", "with --frpc-config: frpc log file named in frpc.toml (Windows); default console")
	fs.StringVar(&o.FrpcAdmin, "frpc-admin", "127.0.0.1:9097", "with --frpc-config: numeric loopback address:port for frpc's admin API")
	fs.StringVar(&o.FrpcRestartCmd, "frpc-restart-cmd", "", "with --frpc-config: command that restarts the frpc service")
	fs.Float64Var(&o.FrpcConfirmTimeout, "frpc-confirm-timeout", 20, "seconds to wait for frpc to register a new generation")
	fs.StringVar(&o.Update, "update", "auto", "auto: follow the control plane's rollout of signed agent releases; off: never update")
	fs.Float64Var(&o.UpdateInterval, "update-interval", 120, "seconds between checks for a rollout target (30-3600)")
	fs.Float64Var(&o.UpdateHealthTimeout, "update-health-timeout", 600, "seconds a new release has to report healthy before it is rolled back (60-3600)")
	fs.StringVar(&c.logFile, "log-file", "", "append the agent's and sing-box's output here (rotated at 10 MB, 5 kept)")
	if err := fs.Parse(argv); err != nil {
		return c, err
	}
	switch {
	case o.CP == "":
		return c, errors.New("--cp is required")
	case o.Run == (o.ReloadCmd != ""):
		return c, errors.New("pass exactly one of --run and --reload-cmd")
	case o.RunReload != "" && o.RunReload != "signal" && o.RunReload != "restart":
		return c, errors.New("--run-reload must be signal or restart")
	case o.RunReload == "signal" && !canHangup:
		return c, errors.New("--run-reload signal is not available on this platform")
	case o.UsageInterval < 10 || o.UsageInterval > 600:
		return c, errors.New("--usage-interval must be between 10 and 600 seconds")
	case o.Iface != "" && !ipsSupported:
		return c, errors.New("--iface is Linux-only; on this system the host's existing local address is the egress IP")
	case o.Update != "auto" && o.Update != "off":
		return c, errors.New("--update must be auto or off")
	case o.UpdateInterval < 30 || o.UpdateInterval > 3600:
		return c, errors.New("--update-interval must be between 30 and 3600 seconds")
	case o.UpdateHealthTimeout < 60 || o.UpdateHealthTimeout > 3600:
		return c, errors.New("--update-health-timeout must be between 60 and 3600 seconds")
	}
	return c, nil
}

func run(argv []string) int {
	c, err := parseArgs(argv, os.Stderr)
	fail := func(msg string) int { fmt.Fprintln(os.Stderr, "ccproxy-exit-agent:", msg); return 2 }
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		return fail(err.Error())
	}
	o := c.Options

	var out io.Writer = os.Stderr
	if c.logFile != "" {
		w, err := openRotating(c.logFile, 10<<20, 5)
		if err != nil {
			return fail(err.Error())
		}
		out = w
	}
	logf := func(format string, a ...any) {
		fmt.Fprintf(out, "%s %s\n", time.Now().Format("2006-01-02T15:04:05"), fmt.Sprintf(format, a...))
	}
	upd := newUpdater(o, argv, logf)
	token, err := readToken(c.tokenFile)
	if err != nil {
		return fail("--token-file: " + err.Error())
	}
	agent, err := NewAgent(o, token, logf, out)
	if err != nil {
		return fail(err.Error())
	}
	agent.attachUpdater(upd)
	logf("ccproxy-exit-agent %s starting (control plane %s)", version, o.CP)
	err = agent.Loop()
	agent.Close()
	if errors.Is(err, errRestartForUpdate) {
		return exitForUpdate // the launcher (or the service manager, then the launcher) starts the chosen release
	}
	if err != nil {
		logf("fatal: %v", err)
		return 1
	}
	return 0
}

// checkArgs: the updater's compatibility test for a candidate binary.
func checkArgs(argv []string) int {
	if _, err := parseArgs(argv, io.Discard); err != nil {
		fmt.Fprintln(os.Stderr, "ccproxy-exit-agent check-args:", err)
		return 2
	}
	return 0
}
