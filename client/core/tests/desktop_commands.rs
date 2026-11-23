//! Issue #3 (CC-07): the desktop connect and logout commands apply their results only for the session that started
//! them. These drive `commands::connect` / `commands::logout`, the exact logic behind the Tauri commands, with the
//! effects injected: the real `sync_once` / `Api::logout` against a local server where timing matters, and hooks
//! where a replacement must land at one precise point.

use anyhow::{anyhow, Result};
use ccproxy_core::api::Api;
use ccproxy_core::commands::{self, ConnectError, Connected, Effects, LoggedOut, Tunnel};
use ccproxy_core::session::{Paths, Session};
use ccproxy_core::sync::{sync_once, SyncOutcome};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const CONFIG: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"v1\"\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"fresh\": true}";
const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn state(tag: &str) -> Paths {
    let d = std::env::temp_dir().join(format!("ccproxy-cmd-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    Paths::new(Some(d)).unwrap()
}

/// One-request HTTP server that answers only after `go` (the request is "in flight" until then).
fn slow_server(response: &'static str) -> (String, mpsc::Sender<()>, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (seen_tx, seen_rx) = mpsc::channel::<String>();
    let h = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).unwrap_or(0);
        seen_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned()).unwrap();
        go_rx.recv().unwrap();
        conn.write_all(response.as_bytes()).unwrap();
    });
    (url, go_tx, seen_rx, h)
}

type SyncFn = dyn Fn(&Paths, &Session) -> Result<SyncOutcome> + Send + Sync;
type LaunchFn = dyn Fn(&Paths) -> Result<()> + Send + Sync;
type LogoutFn = dyn Fn(&Session) -> Result<()> + Send + Sync;

/// Effects with counters; each one defaults to the production behaviour where that is harmless (`sync_once`,
/// `Api::logout`) and to a recorded no-op for the privileged launch.
struct Fx {
    sync: Box<SyncFn>,
    launch: Box<LaunchFn>,
    logout: Box<LogoutFn>,
    launches: AtomicUsize,
    logouts: Mutex<Vec<String>>,
}

impl Fx {
    fn new() -> Fx {
        Fx {
            sync: Box::new(|p, s| sync_once(p, s, "app")),
            launch: Box::new(|_| Ok(())),
            logout: Box::new(|s| Api::new(&s.server)?.logout(&s.token)),
            launches: AtomicUsize::new(0),
            logouts: Mutex::new(Vec::new()),
        }
    }
}

impl Effects for Fx {
    fn sync(&self, paths: &Paths, session: &Session) -> Result<SyncOutcome> {
        (self.sync)(paths, session)
    }
    fn launch_supervisor(&self, paths: &Paths) -> Result<()> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        (self.launch)(paths)
    }
    fn remote_logout(&self, session: &Session) -> Result<()> {
        self.logouts.lock().unwrap().push(session.token.clone());
        (self.logout)(session)
    }
}

/// Signed in as alice, previously disconnected (stop file present), no heartbeat yet.
fn signed_in(paths: &Paths, server: &str) -> Session {
    let s = Session::new(server.into(), "alice".into(), "mac".into(), "alice-token".into());
    s.save(paths).unwrap();
    commands::touch(&paths.stop());
    s
}

/// Sign in again as bob, with bob's config already written.
fn replace_with_bob(paths: &Paths) -> Session {
    let bob = Session::new("http://127.0.0.1:9".into(), "bob".into(), "mac".into(), "bob-token".into());
    bob.save(paths).unwrap();
    fs::write(paths.config(), b"{\"bob\": true}").unwrap();
    fs::write(paths.etag(), b"\"bob\"").unwrap();
    bob
}

fn assert_untouched_by_connect(paths: &Paths, tunnel: &Tunnel, fx: &Fx) {
    assert!(paths.stop().exists(), "stop file left as it was");
    assert!(!paths.heartbeat().exists(), "no heartbeat written");
    assert!(!tunnel.wants_connection(), "connection state unchanged");
    assert_eq!(tunnel.connected_at(), 0);
    assert_eq!(fx.launches.load(Ordering::SeqCst), 0, "supervisor never launched");
}

fn assert_bob_intact(paths: &Paths, bob: &Session) {
    let kept = Session::load(paths).expect("replacement session kept");
    assert_eq!((kept.user.as_str(), kept.id.as_str()), ("bob", bob.id.as_str()));
    assert_eq!(fs::read(paths.config()).unwrap(), b"{\"bob\": true}");
    assert_eq!(fs::read_to_string(paths.etag()).unwrap(), "\"bob\"");
}

// ---- connect --------------------------------------------------------------------------------------------------

#[test]
fn ordinary_connect_starts_the_tunnel() {
    let paths = state("connect");
    let (url, go, _seen, server) = slow_server(CONFIG);
    signed_in(&paths, &url);
    let (tunnel, fx) = (Tunnel::default(), Fx::new());
    go.send(()).unwrap();
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Ok(Connected::Started));
    server.join().unwrap();
    assert_eq!(fs::read(paths.config()).unwrap(), b"{\"fresh\": true}");
    assert!(!paths.stop().exists());
    assert!(paths.heartbeat().exists());
    assert!(tunnel.wants_connection());
    assert!(tunnel.connected_at() > 0);
    assert_eq!(fx.launches.load(Ordering::SeqCst), 1);
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn connect_superseded_during_the_config_request_changes_nothing() {
    let paths = state("connect-inflight");
    let (url, go, seen, server) = slow_server(CONFIG);
    signed_in(&paths, &url);
    let tunnel = Arc::new(Tunnel::default());
    let fx = Arc::new(Fx::new());
    let call = {
        let (paths, tunnel, fx) = (paths.clone(), tunnel.clone(), fx.clone());
        std::thread::spawn(move || commands::connect(&paths, &tunnel, &*fx))
    };
    seen.recv().unwrap(); // the config request is in flight
    let bob = replace_with_bob(&paths);
    go.send(()).unwrap();
    server.join().unwrap();
    assert_eq!(call.join().unwrap(), Ok(Connected::Superseded));
    assert_untouched_by_connect(&paths, &tunnel, &fx);
    assert_bob_intact(&paths, &bob);
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn connect_superseded_between_sync_and_its_side_effects_changes_nothing() {
    let paths = state("connect-after-sync");
    signed_in(&paths, "http://127.0.0.1:9");
    let bob = Arc::new(Mutex::new(None));
    let mut fx = Fx::new();
    let slot = bob.clone();
    // The sync completes for alice; the replacement sign-in lands right after it, before the side effects.
    fx.sync = Box::new(move |p, _| {
        *slot.lock().unwrap() = Some(replace_with_bob(p));
        Ok(SyncOutcome::Updated)
    });
    let tunnel = Tunnel::default();
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Ok(Connected::Superseded));
    assert_untouched_by_connect(&paths, &tunnel, &fx);
    assert_bob_intact(&paths, bob.lock().unwrap().as_ref().unwrap());
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn a_sign_in_during_the_launch_waits_until_the_launch_is_done() {
    let paths = state("connect-launch");
    signed_in(&paths, "http://127.0.0.1:9");
    let mut fx = Fx::new();
    fx.sync = Box::new(|_, _| Ok(SyncOutcome::Unchanged));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = (Mutex::new(done_tx), Mutex::new(done_rx));
    let sign_in = Arc::new(Mutex::new(None));
    let slot = sign_in.clone();
    fx.launch = Box::new(move |p| {
        // While the OS password prompt is up, someone signs in again on another thread.
        let p = p.clone();
        let done = done_tx.lock().unwrap().clone();
        *slot.lock().unwrap() = Some(std::thread::spawn(move || {
            replace_with_bob(&p);
            done.send(()).unwrap();
        }));
        let waited = done_rx.lock().unwrap().recv_timeout(Duration::from_millis(300));
        assert!(waited.is_err(), "the sign-in waits for the launch");
        Ok(())
    });
    let tunnel = Tunnel::default();
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Ok(Connected::Started));
    sign_in.lock().unwrap().take().unwrap().join().unwrap(); // and goes ahead afterwards
    assert_eq!(Session::load(&paths).unwrap().user, "bob");
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn connect_errors_preserve_their_reason_and_diagnostics() {
    let paths = state("connect-errors");
    let tunnel = Tunnel::default();
    let mut fx = Fx::new();
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Err(ConnectError::SignInRequired));
    signed_in(&paths, "http://127.0.0.1:9");
    fx.sync = Box::new(|_, _| Ok(SyncOutcome::SignedOut));
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Err(ConnectError::SessionExpired));
    fx.sync = Box::new(|_, _| Ok(SyncOutcome::Unassigned("no exit".into())));
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Err(ConnectError::Unassigned("no exit".into())));
    fx.sync = Box::new(|_, _| Err(anyhow!("offline")));
    assert_eq!(commands::connect(&paths, &tunnel, &fx), Err(ConnectError::Configuration("offline".into())));
    assert_untouched_by_connect(&paths, &tunnel, &fx);

    fx.sync = Box::new(|_, _| Ok(SyncOutcome::Unchanged));
    fx.launch = Box::new(|_| Err(anyhow!("refused")));
    assert_eq!(commands::connect(&paths, &tunnel, &fx),
               Err(ConnectError::Authorization("refused".into())));
    assert!(!tunnel.wants_connection(), "a refused launch leaves the tunnel off");
    fs::remove_dir_all(&paths.dir).unwrap();
}

// ---- disconnect -----------------------------------------------------------------------------------------------

#[test]
fn ordinary_disconnect_stops_the_tunnel() {
    let paths = state("disconnect");
    let tunnel = Tunnel::default();
    tunnel.want_connected.store(true, Ordering::SeqCst);
    tunnel.request_stop(&paths);
    assert!(!tunnel.wants_connection());
    assert!(paths.stop().exists());
    fs::remove_dir_all(&paths.dir).unwrap();
}

// ---- logout ---------------------------------------------------------------------------------------------------

#[test]
fn ordinary_logout_signs_out_and_stops() {
    let paths = state("logout");
    let (url, go, seen, server) = slow_server(NO_CONTENT);
    signed_in(&paths, &url);
    fs::remove_file(paths.stop()).unwrap();
    fs::write(paths.config(), b"{}").unwrap();
    let tunnel = Tunnel::default();
    tunnel.want_connected.store(true, Ordering::SeqCst);
    go.send(()).unwrap();
    assert_eq!(commands::logout(&paths, &tunnel, &Fx::new()), LoggedOut::SignedOut);
    assert!(seen.recv().unwrap().contains("Bearer alice-token"), "the token is revoked on the server");
    server.join().unwrap();
    assert!(Session::load(&paths).is_none());
    assert!(!paths.config().exists());
    assert!(paths.stop().exists());
    assert!(!tunnel.wants_connection());
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn delayed_logout_reply_leaves_the_replacement_session_alone() {
    let paths = state("logout-inflight");
    let (url, go, seen, server) = slow_server(NO_CONTENT);
    signed_in(&paths, &url);
    let tunnel = Arc::new(Tunnel::default());
    let fx = Arc::new(Fx::new());
    let call = {
        let (paths, tunnel, fx) = (paths.clone(), tunnel.clone(), fx.clone());
        std::thread::spawn(move || commands::logout(&paths, &tunnel, &*fx))
    };
    seen.recv().unwrap(); // alice's logout request is in flight
    let bob = replace_with_bob(&paths);
    go.send(()).unwrap();
    server.join().unwrap();
    assert_eq!(call.join().unwrap(), LoggedOut::Superseded);
    assert_bob_intact(&paths, &bob);
    assert_eq!(*fx.logouts.lock().unwrap(), vec!["alice-token".to_string()], "only alice's token was revoked");
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn logout_stops_and_takes_its_session_snapshot_together_under_the_lock() {
    let paths = state("logout-atomic");
    signed_in(&paths, "http://127.0.0.1:9");
    fs::remove_file(paths.stop()).unwrap();
    let fx = Arc::new({
        let mut fx = Fx::new();
        fx.logout = Box::new(|_| Ok(()));
        fx
    });
    // While a sign-in (or any session change) holds the lock, logout neither stops nor picks a session.
    let held = ccproxy_core::session::lock();
    let call = {
        let (paths, fx) = (paths.clone(), fx.clone());
        std::thread::spawn(move || commands::logout(&paths, &Tunnel::default(), &*fx))
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(!paths.stop().exists(), "no stop before the snapshot");
    assert!(fx.logouts.lock().unwrap().is_empty(), "no token picked yet");
    // The sign-in completes (replacing the session) and releases the lock: logout then stops and signs out that
    // session, consistently, instead of stopping one session and revoking another.
    let bob = Session::new("http://127.0.0.1:9".into(), "bob".into(), "mac".into(), "bob-token".into());
    fs::write(paths.session(), serde_json::to_vec(&bob).unwrap()).unwrap();
    drop(held);
    assert_eq!(call.join().unwrap(), LoggedOut::SignedOut);
    assert_eq!(*fx.logouts.lock().unwrap(), vec!["bob-token".to_string()]);
    assert!(paths.stop().exists());
    assert!(Session::load(&paths).is_none());
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn failed_logout_call_still_signs_out_locally() {
    let paths = state("logout-offline");
    signed_in(&paths, "http://127.0.0.1:9");
    let mut fx = Fx::new();
    fx.logout = Box::new(|_| Err(anyhow!("offline")));
    assert_eq!(commands::logout(&paths, &Tunnel::default(), &fx), LoggedOut::SignedOut);
    assert!(Session::load(&paths).is_none());
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn logout_without_a_session_clears_leftovers() {
    let paths = state("logout-none");
    fs::write(paths.config(), b"{}").unwrap();
    let fx = Fx::new();
    assert_eq!(commands::logout(&paths, &Tunnel::default(), &fx), LoggedOut::NotSignedIn);
    assert!(!paths.config().exists());
    assert!(fx.logouts.lock().unwrap().is_empty(), "no server call without a session");
    fs::remove_dir_all(&paths.dir).unwrap();
}
