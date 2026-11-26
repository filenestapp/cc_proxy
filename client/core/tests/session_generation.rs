//! CC-07: a reply for a session that was signed out and replaced meanwhile must not touch the new session.

use ccproxy_core::session::{Paths, Session};
use ccproxy_core::sync::{sync_once, SyncOutcome};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;

/// One-request HTTP server: waits for `go` before answering with `response`.
fn slow_server(response: &'static str) -> (String, mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel::<()>();
    let h = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf);
        rx.recv().unwrap();
        conn.write_all(response.as_bytes()).unwrap();
    });
    (url, tx, h)
}

const UNAUTHORIZED: &str = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const UNASSIGNED: &str = "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"error\":\"no exit\"}";
const NEW_CONFIG: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"stale\"\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"stale\": true}";

fn state(tag: &str) -> Paths {
    let d: PathBuf = std::env::temp_dir().join(format!("ccproxy-sess-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    Paths::new(Some(d)).unwrap()
}

fn replaced_while_in_flight(response: &'static str, tag: &str) {
    let paths = state(tag);
    let (url, go, server) = slow_server(response);
    let old = Session::new(url.clone(), "alice".into(), "mac".into(), "old-token".into());
    old.save(&paths).unwrap();

    let poll = {
        let (paths, old) = (paths.clone(), old.clone());
        std::thread::spawn(move || sync_once(&paths, &old, "app"))
    };
    std::thread::sleep(std::time::Duration::from_millis(200)); // the request is in flight
    // Sign out and sign in again (possibly as someone else) before the reply arrives.
    Session::clear(&paths);
    let new = Session::new(url, "bob".into(), "mac".into(), "new-token".into());
    new.save(&paths).unwrap();
    fs::write(paths.config(), b"{\"bob\": true}").unwrap();
    fs::write(paths.etag(), b"\"bob\"").unwrap();

    go.send(()).unwrap();
    server.join().unwrap();
    assert_eq!(poll.join().unwrap().unwrap(), SyncOutcome::Superseded, "{tag}");
    let kept = Session::load(&paths).expect("replacement session kept");
    assert_eq!((kept.user.as_str(), kept.id.as_str()), ("bob", new.id.as_str()));
    assert_eq!(fs::read(paths.config()).unwrap(), b"{\"bob\": true}");
    assert_eq!(fs::read_to_string(paths.etag()).unwrap(), "\"bob\"");
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn late_401_for_an_old_session_is_ignored() {
    replaced_while_in_flight(UNAUTHORIZED, "401");
}

#[test]
fn late_409_for_an_old_session_is_ignored() {
    replaced_while_in_flight(UNASSIGNED, "409");
}

#[test]
fn late_config_for_an_old_session_is_ignored() {
    replaced_while_in_flight(NEW_CONFIG, "200");
}

#[test]
fn a_401_for_the_current_session_still_signs_out() {
    let paths = state("current");
    let (url, go, server) = slow_server(UNAUTHORIZED);
    let s = Session::new(url, "alice".into(), "mac".into(), "t".into());
    s.save(&paths).unwrap();
    fs::write(paths.config(), b"{}").unwrap();
    go.send(()).unwrap();
    assert_eq!(sync_once(&paths, &s, "app").unwrap(), SyncOutcome::SignedOut);
    server.join().unwrap();
    assert!(Session::load(&paths).is_none());
    assert!(!paths.config().exists(), "config removed, so a running tunnel stops");
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn a_409_for_the_current_session_still_disconnects() {
    let paths = state("current409");
    let (url, go, server) = slow_server(UNASSIGNED);
    let s = Session::new(url, "alice".into(), "mac".into(), "t".into());
    s.save(&paths).unwrap();
    fs::write(paths.config(), b"{}").unwrap();
    go.send(()).unwrap();
    assert!(matches!(sync_once(&paths, &s, "app").unwrap(), SyncOutcome::Unassigned(_)));
    server.join().unwrap();
    assert!(Session::load(&paths).is_some(), "still signed in");
    assert!(!paths.config().exists());
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn sessions_get_distinct_ids() {
    let a = Session::new("s".into(), "u".into(), "d".into(), "t".into());
    let b = Session::new("s".into(), "u".into(), "d".into(), "t".into());
    assert_ne!(a.id, b.id);
}

#[test]
fn a_legacy_session_keeps_its_binding_when_the_login_username_is_recovered() {
    let paths = state("legacy-username");
    let old = Session::new("http://localhost".into(), "c42".into(), "mac".into(), "token".into());
    old.save(&paths).unwrap();
    fs::write(paths.config(), b"{}").unwrap();
    let session = Session::load(&paths).unwrap();
    assert!(session.login_username.is_none());

    {
        let _guard = ccproxy_core::session::lock();
        assert!(Session::is_current(&paths, &session.id));
        session.save_login_username_locked(&paths, "customer@example.com".into()).unwrap();
    }

    let restored = Session::load(&paths).unwrap();
    assert_eq!(restored.login_username.as_deref(), Some("customer@example.com"));
    assert_eq!(restored.user, old.user);
    assert_eq!(restored.id, old.id);
    assert_eq!(restored.token, old.token);
    assert_eq!(restored.server, old.server);
    assert_eq!(fs::read(paths.config()).unwrap(), b"{}");
    fs::remove_dir_all(&paths.dir).unwrap();
}
