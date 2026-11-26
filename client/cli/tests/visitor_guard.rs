//! Issue #61: the visitor guard (`aifree visitor`) and the app-side controller, driven against a fake frpc that
//! prints frpc 0.72.0's log lines. Unix only: the fake frpc is a shell script. Real frpc runs in the Docker e2e.
#![cfg(unix)]

use ccproxy_core::session::{Paths, Session};
use ccproxy_core::supervisor::Status;
use ccproxy_core::visitor::{self, Launcher, Reason, VisitorProcess};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "frps-token-0123456789abcdef";
const SECRET: &str = "scoped-key-0123456789abcdef";

/// Fake frpc 0.72.0, compiled once per test so it is one process named frpc from start to end (as the real one is):
/// it records how it was started, prints the log lines for the mode in ./fake-mode, then waits.
const FAKE_FRPC_C: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void line(const char *s) { printf("%s\n", s); fflush(stdout); }
int main(int argc, char **argv) {
    FILE *f = fopen("argv.txt", "w");
    for (int i = 1; i < argc; i++) fprintf(f, "%s%s", i > 1 ? " " : "", argv[i]);
    fprintf(f, "\n"); fclose(f);
    const char *token = getenv("FRP_AUTH_TOKEN");
    f = fopen("env-token.txt", "w"); fputs(token ? token : "", f); fclose(f);
    f = fopen("launches.txt", "a"); fprintf(f, "%d\n", (int)getpid()); fclose(f);
    char mode[32] = "ready";
    f = fopen("fake-mode", "r");
    if (f) { if (fscanf(f, "%31s", mode) != 1) strcpy(mode, "ready"); fclose(f); }
    line("2026-11-25 10:00:00.300 [I] [client/service.go:369] try to connect to server...");
    printf("2026-11-25 10:00:00.301 [D] [client/service.go:370] debug dump: token=%s\n", token ? token : ""); fflush(stdout);
    if (!strcmp(mode, "ready")) {
        line("2026-11-25 10:00:00.400 [I] [client/service.go:389] [7f3c] login to server success, get run id [7f3c]");
        line("2026-11-25 10:00:01.123 [I] [client/visitor/visitor_manager.go:135] [7f3c] start visitor success");
        usleep(300000);
        line("2026-11-25 10:00:03.456 [I] [client/visitor/xtcp.go:312] [7f3c] [v] establishing nat hole connection successful, sid [1], remoteAddr [203.0.113.9:41000]");
    } else if (!strcmp(mode, "busy")) {
        line("2026-11-25 10:00:01.000 [W] [client/visitor/visitor_manager.go:132] [7f3c] start error: listen tcp 127.0.0.1:20440: bind: address already in use");
    } else if (!strcmp(mode, "token")) {
        line("2026-11-25 10:00:00.500 [W] [client/service.go:380] connect to server error: token in login doesn't match token from configuration");
        line("login to the server failed: token in login doesn't match token from configuration. With loginFailExit enabled, no additional retries will be attempted");
        return 1;
    } else if (!strcmp(mode, "punch")) {
        line("2026-11-25 10:00:01.123 [I] [client/visitor/visitor_manager.go:135] [7f3c] start visitor success");
        line("2026-11-25 10:00:05.000 [W] [client/visitor/xtcp.go:308] [7f3c] [v] make hole error: wait detect message timeout");
    }
    for (;;) sleep(1000);
}
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
    let src = root.join("fake-frpc.c");
    fs::write(&src, FAKE_FRPC_C).unwrap();
    let built = Command::new("cc").arg("-O0").arg("-o").arg(&frpc).arg(&src).output().expect("a C compiler (cc)");
    assert!(built.status.success(), "cc: {}", String::from_utf8_lossy(&built.stderr));
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
    Command::new(env!("CARGO_BIN_EXE_aifree"))
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
    assert_eq!(visitor::tunnel_view(&e.paths, Some(g.id())).unwrap().0, "running");
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
    let record: visitor::FrpcRecord = serde_json::from_slice(&fs::read(e.paths.visitor_pid()).unwrap()).unwrap();
    assert_eq!((record.frpc, record.guard), (pid as u32, g.id()));
    assert_eq!(Some(record.identity), visitor::process_identity(pid as u32), "the record names this frpc's identity");
    // The visitor runs with the caller's identity, never elevated.
    let uid = String::from_utf8(Command::new("ps").args(["-p", &pid.to_string(), "-o", "uid="]).output().unwrap().stdout).unwrap();
    assert_eq!(uid.trim().parse::<u32>().unwrap(), unsafe { libc::geteuid() });

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
fn the_stop_request_takes_frpc_down_while_the_controller_is_busy() {
    let e = env("requested-stop");
    let mut guard = guard(&e, Stdio::piped());
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let pid = launches(&e.paths)[0];

    ccproxy_core::commands::Tunnel::default().request_stop(&e.paths).unwrap();

    assert!(exited_within(&mut guard, Duration::from_secs(5)).unwrap().success());
    assert!(!alive(pid));
    assert_eq!(state_of(&e.paths).as_deref(), Some("stopped"));
    cleanup(&e);
}

#[test]
fn sign_out_removes_the_files_and_stops_the_visitor() {
    let e = env("signout");
    let mut g = guard(&e, Stdio::piped());
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let pid = launches(&e.paths)[0];
    Session::clear(&e.paths).unwrap();
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
    let (state, message) = visitor::tunnel_view(&e.paths, Some(g.id())).unwrap();
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
    Launcher { cli: PathBuf::from(env!("CARGO_BIN_EXE_aifree")), frpc: e.frpc.clone() }
}

fn running_tunnel(pid: u32, route_generation: u64) -> Status {
    Status {
        state: "running".to_string(),
        pid: Some(pid),
        message: String::new(),
        updated: 100,
        connection_id: None,
        supervisor_pid: None,
        route_generation,
        egress_fingerprint: None,
    }
}

/// PR #64 e2e: after a previous connection's guard was killed (its last word was "ready"), a fresh connection whose
/// hole punch fails must never show connected: only its own guard's status counts.
#[test]
fn a_fresh_connection_ignores_the_ready_status_of_a_previous_one() {
    let e = env("fresh");
    let l = launcher(&e);
    // Connection 1 becomes ready; its guard is then killed outright, leaving "ready" on disk.
    let mut old = guard(&e, Stdio::piped());
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    old.kill().unwrap();
    old.wait().unwrap();
    for pid in launches(&e.paths) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert_eq!(state_of(&e.paths).as_deref(), Some("ready"), "the stale status is still there");

    // Connection 2, same configuration, UDP blocked: starting, then failed, never running.
    mode(&e.paths, "punch");
    let mut p = VisitorProcess::default();
    assert_eq!(visitor::tunnel_view(&e.paths, p.guard_pid(Some(&running_tunnel(1234, 1)))).unwrap().0, "connecting", "before its guard starts");
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let (state, _) = visitor::tunnel_view(&e.paths, p.guard_pid(Some(&running_tunnel(1234, 1)))).unwrap();
        if seen.last() != Some(&state) {
            seen.push(state.clone());
        }
        if state == "failed" {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(seen.last().map(String::as_str), Some("failed"), "{seen:?}");
    assert!(!seen.iter().any(|s| s == "running"), "a stale ready status was shown as connected: {seen:?}");
    drop(p);
    cleanup(&e);
}

#[test]
fn the_controller_restarts_only_for_a_new_configuration() {
    let e = env("controller");
    let l = launcher(&e);
    let mut p = VisitorProcess::default();
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    for _ in 0..5 {
        p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    }
    assert_eq!(launches(&e.paths).len(), 1, "an unchanged configuration keeps its frpc");

    // A rotated token: the old frpc goes, a new one starts.
    let first = launches(&e.paths)[0];
    configure(&e.paths, "frps-token-rotated-0123456789");
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("second launch", || launches(&e.paths).len() == 2);
    assert!(!alive(first));
    assert_eq!(fs::read_to_string(e.paths.dir.join("env-token.txt")).unwrap(), "frps-token-rotated-0123456789");

    // A configuration that fails is not retried in a loop...
    mode(&e.paths, "busy");
    configure(&e.paths, "frps-token-third-0123456789ab");
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("failed", || state_of(&e.paths).as_deref() == Some("failed"));
    wait_for("guard exit", || !p.is_running());
    for _ in 0..20 {
        p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(launches(&e.paths).len(), 3, "a failed configuration must not be restarted");
    // ...until a new Connect asks for it again.
    p.reset();
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("fourth launch", || launches(&e.paths).len() == 4);

    // No visitor configured any more (public-entry host): it stops.
    mode(&e.paths, "ready");
    configure(&e.paths, TOKEN);
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("ready again", || state_of(&e.paths).as_deref() == Some("ready"));
    let last = *launches(&e.paths).last().unwrap();
    for f in [e.paths.visitor_toml(), e.paths.visitor_ca(), e.paths.visitor_token()] {
        fs::remove_file(f).unwrap();
    }
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    assert!(!p.is_running());
    wait_for("frpc to exit", || !alive(last));

    // Dropping the controller (app exit) stops a running visitor.
    configure(&e.paths, TOKEN);
    p.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let last = *launches(&e.paths).last().unwrap();
    drop(p);
    wait_for("frpc to exit after drop", || !alive(last));
    cleanup(&e);
}

#[test]
fn reconnect_and_reload_use_a_new_visitor_for_the_new_tun_routes() {
    let e = env("tunnel-generation");
    let launcher = launcher(&e);
    let mut visitor = VisitorProcess::default();
    visitor.ensure(&e.paths, &launcher, None).unwrap();
    assert!(!visitor.is_running(), "the visitor waits for the system routes");

    let mut first = running_tunnel(1234, 1);
    visitor.ensure(&e.paths, &launcher, Some(&first)).unwrap();
    wait_for("first visitor ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let initial_pid = launches(&e.paths)[0];

    first.updated += 1;
    visitor.ensure(&e.paths, &launcher, Some(&first)).unwrap();
    assert_eq!(launches(&e.paths), vec![initial_pid], "a status message does not replace the routes");

    let reloaded = running_tunnel(1234, 2);
    assert!(visitor.guard_pid(Some(&reloaded)).is_none(), "a prior route's guard must not report ready");
    visitor.ensure(&e.paths, &launcher, Some(&reloaded)).unwrap();
    wait_for("visitor on reloaded routes", || launches(&e.paths).len() == 2);
    assert!(!alive(initial_pid));
    let reload_pid = launches(&e.paths)[1];

    visitor.ensure(&e.paths, &launcher, None).unwrap();
    assert!(!alive(reload_pid), "disconnect stops the visitor");
    let restarted = running_tunnel(1235, 1);
    visitor.ensure(&e.paths, &launcher, Some(&restarted)).unwrap();
    wait_for("visitor on the reconnected TUN", || launches(&e.paths).len() == 3);
    assert!(visitor.guard_pid(Some(&restarted)).is_some());
    visitor.stop();
    cleanup(&e);
}

/// PR #64 review: opening the desktop app again must not take down the visitor of the instance that is connected.
/// The cleanup a launch runs (kill_stale) leaves an frpc alone while its guard runs, whichever process calls it.
#[test]
fn a_second_launch_keeps_the_live_visitor() {
    let e = env("second-launch");
    let l = launcher(&e);
    let mut first = VisitorProcess::default();
    first.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let pid = launches(&e.paths)[0];

    // A second launch, and the primary's own cleanup later on: neither touches the working visitor.
    for _ in 0..3 {
        visitor::kill_stale(&e.paths);
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(alive(pid), "the live frpc must survive the cleanup");
    assert!(first.is_running());
    assert_eq!(state_of(&e.paths).as_deref(), Some("ready"));
    assert!(e.paths.visitor_pid().exists(), "the pid file of a live visitor stays");
    // And the first instance still controls it: a later ensure keeps it, a stop ends it.
    first.ensure(&e.paths, &l, Some(&running_tunnel(1234, 1))).unwrap();
    assert_eq!(launches(&e.paths).len(), 1);
    drop(first);
    wait_for("frpc to exit", || !alive(pid));
    cleanup(&e);
}

/// A guard killed outright leaves an orphaned frpc on macOS (Linux kills it by parent-death signal). The next owner
/// of the session removes it.
#[test]
fn an_orphan_whose_guard_was_killed_is_removed() {
    let e = env("orphan");
    let mut g = guard(&e, Stdio::piped());
    wait_for("ready", || state_of(&e.paths).as_deref() == Some("ready"));
    let pid = launches(&e.paths)[0];
    g.kill().unwrap();
    g.wait().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    if cfg!(target_os = "macos") {
        assert!(alive(pid), "on macOS the frpc of a killed guard survives as an orphan");
    }
    visitor::kill_stale(&e.paths);
    wait_for("the orphan to exit", || !alive(pid));
    assert!(!e.paths.visitor_pid().exists());
    cleanup(&e);
}

fn record(paths: &Paths, frpc: u32, guard: u32, identity: &str) {
    let r = visitor::FrpcRecord { frpc, guard, identity: identity.into() };
    fs::write(paths.visitor_pid(), serde_json::to_vec(&r).unwrap()).unwrap();
}

fn running(child: &mut Child) -> bool {
    child.try_wait().unwrap().is_none()
}

#[test]
fn only_a_verified_orphan_is_killed() {
    let e = env("stale");
    let root = e.paths.dir.parent().unwrap().to_path_buf();
    let frpc = e.frpc.clone();
    let dead_guard = {
        let mut c = Command::new("true").spawn().unwrap();
        let id = c.id();
        c.wait().unwrap();
        id
    };
    let start = |program: &Path| {
        let c = Command::new(program).arg("1000").current_dir(&root).stdout(Stdio::null()).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        c
    };

    // A process that is not frpc is never killed, even with its own identity recorded.
    let mut stray = start(Path::new("/bin/sleep"));
    record(&e.paths, stray.id(), dead_guard, &visitor::process_identity(stray.id()).unwrap());
    visitor::kill_stale(&e.paths);
    assert!(running(&mut stray), "a process that is not frpc is left alone");
    stray.kill().unwrap();
    stray.wait().unwrap();

    // A bare pid (no guard, no identity) cannot prove ownership: its frpc is left alone.
    let mut unproven = start(&frpc);
    fs::write(e.paths.visitor_pid(), unproven.id().to_string()).unwrap();
    visitor::kill_stale(&e.paths);
    assert!(running(&mut unproven), "an frpc whose ownership is unknown is left alone");
    unproven.kill().unwrap();
    unproven.wait().unwrap();

    // PID reuse: the recorded guard is dead and a process named frpc sits at the recorded pid, but it is not the frpc
    // that was recorded (another start time and command line). It is preserved, and the stale record dropped.
    let mut reused = start(&frpc);
    assert!(running(&mut reused));
    record(&e.paths, reused.id(), dead_guard, &format!("Thu Jan  1 00:00:00 1970     {} -c /old/frpc-visitor.toml", frpc.display()));
    visitor::kill_stale(&e.paths);
    std::thread::sleep(Duration::from_millis(200));
    assert!(running(&mut reused), "an unrelated frpc that reused the pid is preserved");
    assert!(!e.paths.visitor_pid().exists(), "the stale record is dropped");
    // Same pid and name, identity recorded for a different command line: also not ours.
    let id = visitor::process_identity(reused.id()).unwrap();
    record(&e.paths, reused.id(), dead_guard, &id.replace("1000", "999"));
    visitor::kill_stale(&e.paths);
    std::thread::sleep(Duration::from_millis(200));
    assert!(running(&mut reused), "a different command line is a different process");
    reused.kill().unwrap();
    reused.wait().unwrap();

    // The recorded frpc itself, its guard gone and not its child: the orphan is killed.
    let mut left = start(&frpc);
    assert!(running(&mut left), "the stand-in frpc runs");
    record(&e.paths, left.id(), dead_guard, &visitor::process_identity(left.id()).unwrap());
    visitor::kill_stale(&e.paths);
    assert!(exited_within(&mut left, Duration::from_secs(5)).is_some(), "the orphaned frpc is killed");
    assert!(!e.paths.visitor_pid().exists());
    cleanup(&e);
}

/// PR #64 review: the visitor never runs with elevated rights. `aifree up` (root) has no visitor option, and the
/// guard and `aifree headless` refuse root. The refusal itself can only be exercised as root: here when the tests
/// run as root, and always in the Docker e2e (controlplane/test/xtcp/desktop-phase.sh).
#[test]
fn the_privileged_cli_path_runs_no_visitor() {
    let ccproxy = env!("CARGO_BIN_EXE_aifree");
    let out = Command::new(ccproxy).args(["up", "--visitor"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "clap rejects the removed flag");
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument '--visitor'"));
    let help = String::from_utf8(Command::new(ccproxy).args(["up", "--help"]).output().unwrap().stdout).unwrap();
    assert!(!help.contains("visitor") && !help.contains("frpc"), "{help}");

    if unsafe { libc::geteuid() } == 0 {
        let e = env("root");
        for args in [vec!["visitor", "--frpc"], vec!["headless", "--frpc"]] {
            let out = Command::new(ccproxy).arg("--state-dir").arg(&e.paths.dir).args(&args).arg(&e.frpc)
                .stdin(Stdio::null()).output().unwrap();
            assert!(!out.status.success());
            assert!(String::from_utf8_lossy(&out.stderr).contains("must not run as root"), "{args:?}");
        }
        assert!(launches(&e.paths).is_empty(), "no frpc was started as root");
        cleanup(&e);
    } else {
        eprintln!("as a regular user: the root refusal is covered by the Docker e2e");
    }
}
