//! Issue #61: the visitor guard (`ccproxy visitor`) and the app-side controller, driven against a fake frpc that
//! prints frpc 0.72.0's log lines. Unix only: the fake frpc is a shell script. Real frpc runs in the Docker e2e.
#![cfg(unix)]

use ccproxy_core::session::{Paths, Session};
use ccproxy_core::visitor::{self, Launcher, Reason, VisitorProcess};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "frps-token-0123456789abcdef";
const SECRET: &str = "scoped-key-0123456789abcdef";

const FAKE_FRPC: &str = r#"#!/bin/sh
# Fake frpc 0.72.0: records how it was started, then prints the log lines for the mode in ./fake-mode.
echo "$@" > argv.txt
printf '%s' "$FRP_AUTH_TOKEN" > env-token.txt
echo $$ >> launches.txt
mode=$(cat fake-mode 2>/dev/null || echo ready)
echo "2026-11-25 10:00:00.300 [I] [client/service.go:369] try to connect to server..."
echo "2026-11-25 10:00:00.301 [D] [client/service.go:370] debug dump: token=$FRP_AUTH_TOKEN"
case "$mode" in
  ready)
    echo "2026-11-25 10:00:00.400 [I] [client/service.go:389] [7f3c] login to server success, get run id [7f3c]"
    echo "2026-11-25 10:00:01.123 [I] [client/visitor/visitor_manager.go:135] [7f3c] start visitor success"
    sleep 0.3
    echo "2026-11-25 10:00:03.456 [I] [client/visitor/xtcp.go:312] [7f3c] [v] establishing nat hole connection successful, sid [1], remoteAddr [203.0.113.9:41000]"
    ;;
  busy)
    echo "2026-11-25 10:00:01.000 [W] [client/visitor/visitor_manager.go:132] [7f3c] start error: listen tcp 127.0.0.1:20440: bind: address already in use"
    ;;
  token)
    echo "2026-11-25 10:00:00.500 [W] [client/service.go:380] connect to server error: token in login doesn't match token from configuration"
    echo "login to the server failed: token in login doesn't match token from configuration. With loginFailExit enabled, no additional retries will be attempted"
    exit 1
    ;;
  punch)
    echo "2026-11-25 10:00:01.123 [I] [client/visitor/visitor_manager.go:135] [7f3c] start visitor success"
    echo "2026-11-25 10:00:05.000 [W] [client/visitor/xtcp.go:308] [7f3c] [v] make hole error: wait detect message timeout"
    ;;
esac
exec sleep 1000
"#;

struct Env {
    paths: Paths,
    frpc: PathBuf,
}

fn env(tag: &str) -> Env {
    let root = std::env::temp_dir().join(format!("ccproxy-guard-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let paths = Paths::new(Some(root.join("state"))).unwrap();
    let frpc = root.join("frpc");
    fs::write(&frpc, FAKE_FRPC).unwrap();
    fs::set_permissions(&frpc, fs::Permissions::from_mode(0o755)).unwrap();
    Session::new("http://127.0.0.1:9".into(), "bob".into(), "bob-mac".into(), "device-token".into()).save(&paths).unwrap();
    configure(&paths, TOKEN);
    Env { paths, frpc }
}

/// Visitor files as `sync_visitor` writes them (their content does not matter to the fake frpc).
fn configure(paths: &Paths, token: &str) {
    let toml = format!("serverAddr = \"frps.example.com\"\n[[visitors]]\nsecretKey = \"{SECRET}\"\nbindPort = 20440\n");
    fs::write(paths.visitor_toml(), toml).unwrap();
    fs::write(paths.visitor_ca(), "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
    fs::write(paths.visitor_token(), token).unwrap();
    fs::write(paths.visitor_info(), r#"{"proxy_name":"ccproxy-nat-direct-20440","bind_port":20440,"exit_state":"ready"}"#).unwrap();
}

fn mode(paths: &Paths, m: &str) {
    fs::write(paths.dir.join("fake-mode"), m).unwrap();
}

fn guard(e: &Env, stdin: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ccproxy"))
        .arg("--state-dir").arg(&e.paths.dir).arg("visitor").arg("--frpc").arg(&e.frpc)
        .stdin(stdin).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap()
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn state_of(paths: &Paths) -> Option<String> {
    visitor::read_status(paths).map(|s| s.state)
}

fn launches(paths: &Paths) -> Vec<i32> {
    fs::read_to_string(paths.dir.join("launches.txt")).unwrap_or_default().lines().filter_map(|l| l.parse().ok()).collect()
}

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn exited_within(child: &mut Child, d: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn cleanup(e: &Env) {
    for pid in launches(&e.paths) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let _ = fs::remove_dir_all(e.paths.dir.parent().unwrap());
}

#[test]
fn guard_reports_ready_keeps_the_token_off_the_command_line_and_stops_when_stdin_closes() {
    let e = env("ready");
    let mut g = guard(&e, Stdio::piped());
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    assert_eq!(visitor::tunnel_view(&e.paths).unwrap().0, "running");
    let pid = launches(&e.paths)[0];
    assert!(alive(pid));
    let dir = &e.paths.dir;
    let argv = fs::read_to_string(dir.join("argv.txt")).unwrap();
    assert_eq!(argv.trim(), format!("-c {}", e.paths.visitor_toml().display()));
    assert!(!argv.contains(TOKEN));
    assert_eq!(fs::read_to_string(dir.join("env-token.txt")).unwrap(), TOKEN, "frpc gets the token through its environment");
    let log = fs::read_to_string(e.paths.visitor_log()).unwrap();
    assert!(log.contains("token=[redacted]") && !log.contains(TOKEN) && !log.contains(SECRET), "{log}");
    assert_eq!(fs::metadata(e.paths.visitor_log()).unwrap().permissions().mode() & 0o777, 0o600);
    let status = fs::read_to_string(e.paths.visitor_status()).unwrap();
    assert!(!status.contains(TOKEN) && !status.contains(SECRET));
    assert_eq!(fs::read_to_string(e.paths.visitor_pid()).unwrap().trim(), pid.to_string());

    drop(g.stdin.take()); // Disconnect: the app closes the guard's stdin.
    assert!(exited_within(&mut g, Duration::from_secs(5)).unwrap().success());
    assert!(!alive(pid), "frpc must stop with the guard");
    assert_eq!(state_of(&e.paths).as_deref(), Some("stopped"));
    assert!(!e.paths.visitor_pid().exists());
    cleanup(&e);
}

#[test]
fn a_crashed_app_takes_frpc_down() {
    let e = env("crash");
    // The "app" holds the write end of the guard's stdin; SIGKILL it as a crash would.
    let mut app = Command::new("sleep").arg("1000").stdout(Stdio::piped()).spawn().unwrap();
    let mut g = guard(&e, Stdio::from(app.stdout.take().unwrap()));
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let pid = launches(&e.paths)[0];
    app.kill().unwrap();
    app.wait().unwrap();
    assert!(exited_within(&mut g, Duration::from_secs(5)).is_some(), "the guard must notice the app is gone");
    wait_for("frpc to exit", || !alive(pid));
    cleanup(&e);
}

#[test]
fn sign_out_removes_the_files_and_stops_the_visitor() {
    let e = env("signout");
    let mut g = guard(&e, Stdio::piped());
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let pid = launches(&e.paths)[0];
    Session::clear(&e.paths);
    assert!(exited_within(&mut g, Duration::from_secs(5)).is_some());
    assert!(!alive(pid));
    for p in [e.paths.visitor_toml(), e.paths.visitor_ca(), e.paths.visitor_token(), e.paths.visitor_info()] {
        assert!(!p.exists(), "{}", p.display());
    }
    cleanup(&e);
}

fn failed_with(tag: &str, m: &str, reason: Reason) {
    let e = env(tag);
    mode(&e.paths, m);
    let mut g = guard(&e, Stdio::piped());
    let status = exited_within(&mut g, Duration::from_secs(10)).expect("the guard stops on a fatal frpc error");
    assert!(!status.success());
    let s = visitor::read_status(&e.paths).unwrap();
    assert_eq!((s.state.as_str(), s.reason), ("failed", Some(reason)), "{s:?}");
    assert_eq!(s.message, reason.message(&s.message_detail(), 20440));
    let (state, message) = visitor::tunnel_view(&e.paths).unwrap();
    assert_eq!((state.as_str(), message.as_str()), ("failed", s.message.as_str()));
    for pid in launches(&e.paths) {
        wait_for("frpc to exit", || !alive(pid));
    }
    cleanup(&e);
}

trait Detail {
    fn message_detail(&self) -> String;
}

impl Detail for visitor::VisitorStatus {
    /// The frpc detail inside a message: the text in the last parentheses.
    fn message_detail(&self) -> String {
        let m = &self.message;
        match (m.find(" ("), m.rfind(')')) {
            (Some(a), Some(b)) if b > a => m[a + 2..b].to_string(),
            _ => String::new(),
        }
    }
}

#[test]
fn a_busy_local_port_fails_with_its_own_message() {
    failed_with("busy", "busy", Reason::LocalPortBusy);
}

#[test]
fn a_refused_token_fails_with_its_own_message() {
    failed_with("token", "token", Reason::TokenRefused);
}

#[test]
fn a_failed_hole_punch_is_reported_while_frpc_keeps_its_bounded_retries() {
    let e = env("punch");
    mode(&e.paths, "punch");
    let mut g = guard(&e, Stdio::piped());
    wait_for("failed", || state_of(&e.paths).as_deref() == Some("failed"));
    let s = visitor::read_status(&e.paths).unwrap();
    assert_eq!(s.reason, Some(Reason::HolePunchFailed));
    assert!(s.message.contains("never relayed"), "{}", s.message);
    assert!(g.try_wait().unwrap().is_none(), "frpc keeps retrying on its own schedule");
    drop(g.stdin.take());
    assert!(exited_within(&mut g, Duration::from_secs(5)).is_some());
    cleanup(&e);
}

fn launcher(e: &Env) -> Launcher {
    Launcher { ccproxy: PathBuf::from(env!("CARGO_BIN_EXE_ccproxy")), frpc: e.frpc.clone() }
}

#[test]
fn the_controller_restarts_only_for_a_new_configuration() {
    let e = env("controller");
    let l = launcher(&e);
    let mut p = VisitorProcess::default();
    p.ensure(&e.paths, &l).unwrap();
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    for _ in 0..5 {
        p.ensure(&e.paths, &l).unwrap();
    }
    assert_eq!(launches(&e.paths).len(), 1, "an unchanged configuration keeps its frpc");

    // A rotated token: the old frpc goes, a new one starts.
    let first = launches(&e.paths)[0];
    configure(&e.paths, "frps-token-rotated-0123456789");
    p.ensure(&e.paths, &l).unwrap();
    wait_for("second launch", || launches(&e.paths).len() == 2);
    assert!(!alive(first));
    assert_eq!(fs::read_to_string(e.paths.dir.join("env-token.txt")).unwrap(), "frps-token-rotated-0123456789");

    // A configuration that fails is not retried in a loop...
    mode(&e.paths, "busy");
    configure(&e.paths, "frps-token-third-0123456789ab");
    p.ensure(&e.paths, &l).unwrap();
    wait_for("failed", || state_of(&e.paths).as_deref() == Some("failed"));
    wait_for("guard exit", || !p.is_running());
    for _ in 0..20 {
        p.ensure(&e.paths, &l).unwrap();
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(launches(&e.paths).len(), 3, "a failed configuration must not be restarted");
    // ...until a new Connect asks for it again.
    p.reset();
    p.ensure(&e.paths, &l).unwrap();
    wait_for("fourth launch", || launches(&e.paths).len() == 4);

    // No visitor configured any more (public-entry host): it stops.
    mode(&e.paths, "ready");
    configure(&e.paths, TOKEN);
    p.ensure(&e.paths, &l).unwrap();
    wait_for("ready again", || state_of(&e.paths).as_deref() == Some("ready"));
    let last = *launches(&e.paths).last().unwrap();
    for f in [e.paths.visitor_toml(), e.paths.visitor_ca(), e.paths.visitor_token()] {
        fs::remove_file(f).unwrap();
    }
    p.ensure(&e.paths, &l).unwrap();
    assert!(!p.is_running());
    wait_for("frpc to exit", || !alive(last));

    // Dropping the controller (app exit) stops a running visitor.
    configure(&e.paths, TOKEN);
    p.ensure(&e.paths, &l).unwrap();
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let last = *launches(&e.paths).last().unwrap();
    drop(p);
    wait_for("frpc to exit after drop", || !alive(last));
    cleanup(&e);
}

#[test]
fn a_leftover_frpc_is_killed_but_an_unrelated_process_is_not() {
    let e = env("stale");
    let mut stray = Command::new("sleep").arg("1000").spawn().unwrap();
    fs::write(e.paths.visitor_pid(), stray.id().to_string()).unwrap();
    visitor::kill_stale(&e.paths);
    assert!(stray.try_wait().unwrap().is_none(), "a process that is not frpc is left alone");
    assert!(!e.paths.visitor_pid().exists());
    stray.kill().unwrap();
    stray.wait().unwrap();

    // A real leftover: an frpc-named process.
    let named = e.paths.dir.parent().unwrap().join("bin");
    fs::create_dir_all(&named).unwrap();
    let frpc = named.join("frpc");
    fs::copy(Path::new("/bin/sleep"), &frpc).unwrap();
    let mut left = Command::new(&frpc).arg("1000").spawn().unwrap();
    fs::write(e.paths.visitor_pid(), left.id().to_string()).unwrap();
    visitor::kill_stale(&e.paths);
    assert!(exited_within(&mut left, Duration::from_secs(5)).is_some(), "the leftover frpc is killed");
    cleanup(&e);
}
