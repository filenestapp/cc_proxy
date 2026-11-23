// Command ccproxy-exit-agent keeps an exit node's sing-box in step with the CC Proxy control plane.
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
//	ccproxy-exit-agent ips up|down IFACE FILE      Linux: add the addresses in FILE to IFACE (boot unit), or
//	                                               remove the ones this agent added (recorded in owned-ips.txt)
package main

import (
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
		}
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

func run(argv []string) int {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("ccproxy-exit-agent", flag.ContinueOnError)
	var o Options
	var tokenFile, logFile, ipsScript string
	fs.StringVar(&o.CP, "cp", "", "control plane base URL (https)")
	fs.StringVar(&o.CAFile, "cafile", "", "CA bundle for a private control-plane certificate")
	fs.StringVar(&tokenFile, "token-file", "", "read the agent token from this file instead of CP_AGENT_TOKEN")
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
	fs.Float64Var(&o.ConfirmTimeout, "confirm-timeout", 15, "seconds to wait for sing-box to confirm a reloaded config")
	fs.BoolVar(&o.Once, "once", false, "sync once and exit")
	fs.BoolVar(&o.Run, "run", false, "supervise sing-box as a child process")
	fs.StringVar(&o.ReloadCmd, "reload-cmd", "", "command that makes sing-box load --config")
	fs.StringVar(&o.RunReload, "run-reload", "", "with --run: signal (SIGHUP) or restart; default signal, restart on Windows")
	fs.StringVar(&logFile, "log-file", "", "append the agent's and sing-box's output here (rotated at 10 MB, 5 kept)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	fail := func(msg string) int { fmt.Fprintln(os.Stderr, "ccproxy-exit-agent:", msg); return 2 }
	if o.CP == "" {
		return fail("--cp is required")
	}
	if o.Run == (o.ReloadCmd != "") {
		return fail("pass exactly one of --run and --reload-cmd")
	}
	if o.RunReload != "" && o.RunReload != "signal" && o.RunReload != "restart" {
		return fail("--run-reload must be signal or restart")
	}
	if o.RunReload == "signal" && !canHangup {
		return fail("--run-reload signal is not available on this platform")
	}
	if o.Iface != "" && !ipsSupported {
		return fail("--iface is Linux-only; on this system the host's existing local address is the egress IP")
	}

	var out io.Writer = os.Stderr
	if logFile != "" {
		w, err := openRotating(logFile, 10<<20, 5)
		if err != nil {
			return fail(err.Error())
		}
		out = w
	}
	logf := func(format string, a ...any) {
		fmt.Fprintf(out, "%s %s\n", time.Now().Format("2006-01-02T15:04:05"), fmt.Sprintf(format, a...))
	}
	token, err := readToken(tokenFile)
	if err != nil {
		return fail("--token-file: " + err.Error())
	}
	agent, err := NewAgent(o, token, logf, out)
	if err != nil {
		return fail(err.Error())
	}
	logf("ccproxy-exit-agent %s starting (control plane %s)", version, o.CP)
	if err := agent.Loop(); err != nil {
		logf("fatal: %v", err)
		return 1
	}
	agent.Close()
	return 0
}
