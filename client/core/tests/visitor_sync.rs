//! Issue #61: the desktop app keeps the XTCP visitor files in step with `GET /v1/xtcp-visitor`, next to the sing-box
//! config: written privately, replaced on rotation, removed for a public-entry host, a 409, a 401 and sign-out.

use ccproxy_core::session::{Paths, Session};
use ccproxy_core::sync::{sync_with_visitor, SyncOutcome};
use ccproxy_core::visitor::{self, sync_visitor, VisitorSync};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIBATAKBggqhkjOPQQDAjAX\n-----END CERTIFICATE-----\n";

type Routes = Arc<Mutex<Vec<(String, String)>>>;

/// A tiny HTTP server: answers each request with the response registered for its path, and records the requests
/// (path and If-None-Match) it saw.
struct Server {
    url: String,
    routes: Arc<Mutex<std::collections::HashMap<String, String>>>,
    seen: Routes,
}

fn server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let routes: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::default();
    let seen: Routes = Arc::default();
    let (r, s) = (routes.clone(), seen.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let path = first.split_whitespace().nth(1).unwrap_or("").split('?').next().unwrap().to_string();
            let mut etag = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("if-none-match:") {
                    etag = v.trim().to_string();
                }
            }
            s.lock().unwrap().push((path.clone(), etag));
            let resp = r.lock().unwrap().get(&path).cloned().unwrap_or_else(|| status(404, ""));
            let _ = conn.write_all(resp.as_bytes());
        }
    });
    Server { url, routes, seen }
}

impl Server {
    fn route(&self, path: &str, response: String) {
        self.routes.lock().unwrap().insert(path.into(), response);
    }
}

fn status(code: u16, body: &str) -> String {
    format!("HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len())
}

fn ok(etag: &str, body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"{etag}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len())
}

fn visitor_json(token: &str, port: u16, exit_state: &str) -> String {
    serde_json::json!({
        "server_addr": "frps.example.com", "server_port": 7003, "tls_server_name": "frps.example.com",
        "ca_pem": CA, "auth_token": token, "proxy_name": format!("ccproxy-nat-direct-{port}"),
        "secret_key": "scoped-key-0123456789abcdef", "bind_addr": "127.0.0.1", "bind_port": port,
        "exit_state": exit_state,
    }).to_string()
}

fn singbox_json(server: &str, port: u16) -> String {
    serde_json::json!({"outbounds": [{"type": "vless", "tag": "egress", "server": server, "server_port": port}]}).to_string()
}

fn state(tag: &str) -> Paths {
    let d = std::env::temp_dir().join(format!("ccproxy-visitor-sync-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    Paths::new(Some(d)).unwrap()
}

fn signed_in(paths: &Paths, url: &str) -> Session {
    let s = Session::new(url.into(), "bob".into(), "bob-mac".into(), "device-token".into());
    s.save(paths).unwrap();
    s
}

fn config_files(paths: &Paths) -> Vec<std::path::PathBuf> {
    vec![paths.visitor_toml(), paths.visitor_ca(), paths.visitor_token(), paths.visitor_info(), paths.visitor_etag()]
}

#[test]
fn visitor_settings_follow_the_control_plane() {
    let paths = state("follow");
    let srv = server();
    let session = signed_in(&paths, &srv.url);

    srv.route("/v1/xtcp-visitor", ok("v1", &visitor_json("frps-token-0123456789abcdef", 20440, "pending")));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::Updated);
    for p in config_files(&paths) {
        assert!(p.exists(), "{}", p.display());
        #[cfg(unix)]
        if p != paths.visitor_etag() {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
        }
    }
    let toml = fs::read_to_string(paths.visitor_toml()).unwrap();
    assert!(toml.contains("bindPort = 20440") && !toml.contains("frps-token-0123456789abcdef"), "{toml}");
    assert!(toml.contains(&format!("{:?}", paths.visitor_ca().display().to_string())), "the CA path is the local file: {toml}");
    assert_eq!(fs::read_to_string(paths.visitor_ca()).unwrap(), CA);
    assert_eq!(visitor::read_info(&paths).unwrap().exit_state, "pending");
    let fp = visitor::fingerprint(&paths).unwrap();

    // The next poll sends the ETag; 304 changes nothing.
    srv.route("/v1/xtcp-visitor", status(304, ""));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::Unchanged);
    assert_eq!(srv.seen.lock().unwrap().last().unwrap().1, "\"v1\"");

    // The exit host confirmed its mapping: new ETag, same frpc configuration (no restart needed).
    srv.route("/v1/xtcp-visitor", ok("v2", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::Updated);
    assert_eq!(visitor::fingerprint(&paths).unwrap(), fp);
    assert_eq!(visitor::read_info(&paths).unwrap().exit_state, "ready");

    // The frps token is rotated: the configuration the guard runs changes.
    srv.route("/v1/xtcp-visitor", ok("v3", &visitor_json("frps-token-rotated-0123456789", 20440, "ready")));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::Updated);
    assert_ne!(visitor::fingerprint(&paths).unwrap(), fp);

    // A malformed answer is refused and leaves the working files alone.
    srv.route("/v1/xtcp-visitor", ok("bad", &visitor_json("{{ .Envs.HOME }}-0123456789", 20440, "ready")));
    assert!(sync_visitor(&paths, &session).is_err());
    assert_eq!(fs::read_to_string(paths.visitor_token()).unwrap(), "frps-token-rotated-0123456789");

    // Moved to a public-entry host: 204 removes the visitor.
    srv.route("/v1/xtcp-visitor", status(204, ""));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::NotNeeded);
    assert!(config_files(&paths).iter().all(|p| !p.exists()));
    assert!(!visitor::required(&paths));

    // 409: the reason is kept for the app, the files go.
    srv.route("/v1/xtcp-visitor", ok("v4", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    sync_visitor(&paths, &session).unwrap();
    srv.route("/v1/xtcp-visitor", status(409, r#"{"error":"your exit IP has no XTCP mapping yet; ask the admin"}"#));
    assert_eq!(sync_visitor(&paths, &session).unwrap(),
               VisitorSync::Unavailable("your exit IP has no XTCP mapping yet; ask the admin".into()));
    assert!(config_files(&paths).iter().all(|p| !p.exists()));

    // 401: the session and everything derived from it go.
    srv.route("/v1/xtcp-visitor", ok("v5", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    sync_visitor(&paths, &session).unwrap();
    srv.route("/v1/xtcp-visitor", status(401, ""));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::SignedOut);
    assert!(Session::load(&paths).is_none());
    assert!(visitor::files(&paths).iter().all(|p| !p.exists()));
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn the_combined_sync_requires_the_tunnel_to_dial_the_visitor() {
    let paths = state("combined");
    let srv = server();
    let session = signed_in(&paths, &srv.url);

    // A public-entry host: the config alone, no visitor.
    srv.route("/v1/config", ok("c1", &singbox_json("203.0.113.5", 20440)));
    srv.route("/v1/xtcp-visitor", status(204, ""));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Updated);
    assert!(!visitor::required(&paths));

    // An XTCP host whose public entry is 127.0.0.1: visitor written.
    srv.route("/v1/config", ok("c2", &singbox_json("127.0.0.1", 20440)));
    srv.route("/v1/xtcp-visitor", ok("v1", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Updated);
    assert!(visitor::required(&paths));

    // Only the visitor changed: still Updated.
    srv.route("/v1/config", status(304, ""));
    srv.route("/v1/xtcp-visitor", ok("v2", &visitor_json("frps-token-rotated-0123456789", 20440, "ready")));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Updated);
    srv.route("/v1/xtcp-visitor", status(304, ""));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Unchanged);

    // The tunnel config dials another address: a distinct, explained failure, and no visitor left behind.
    srv.route("/v1/config", ok("c3", &singbox_json("203.0.113.5", 20440)));
    srv.route("/v1/xtcp-visitor", ok("v3", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    match sync_with_visitor(&paths, &session, "app").unwrap() {
        SyncOutcome::XtcpUnavailable(m) => assert!(m.contains("127.0.0.1") && m.contains("20440"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(!visitor::required(&paths));

    // No exit assigned: the visitor goes with the config.
    srv.route("/v1/config", ok("c4", &singbox_json("127.0.0.1", 20440)));
    srv.route("/v1/xtcp-visitor", ok("v4", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    sync_with_visitor(&paths, &session, "app").unwrap();
    srv.route("/v1/config", status(409, r#"{"error":"no exit"}"#));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Unassigned("no exit".into()));
    assert!(!visitor::required(&paths) && !paths.config().exists());
    fs::remove_dir_all(&paths.dir).unwrap();
}

/// What the desktop app runs on Connect, with the real sync and a stub launch.
struct ConnectFx;

impl ccproxy_core::commands::Effects for ConnectFx {
    fn sync(&self, paths: &Paths, session: &Session) -> anyhow::Result<SyncOutcome> {
        sync_with_visitor(paths, session, "app")
    }
    fn launch_supervisor(&self, _: &Paths, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn remote_logout(&self, _: &Session) -> anyhow::Result<()> {
        Ok(())
    }
}

/// PR #64 review: a desktop release that ships ahead of the server must still connect. A control plane from before
/// issue #61 answers 404 for /v1/xtcp-visitor; the client then behaves as before the feature.
#[test]
fn an_older_control_plane_without_the_visitor_endpoint_still_connects() {
    use ccproxy_core::commands::{connect, ConnectError, Connected, Tunnel};
    let paths = state("older");
    let srv = server();
    let session = signed_in(&paths, &srv.url);
    // The old server's router: 404 with its JSON error body.
    srv.route("/v1/xtcp-visitor", status(404, r#"{"error":"not found"}"#));

    // A public-entry host: Connect succeeds as it did before.
    srv.route("/v1/config", ok("c1", &singbox_json("203.0.113.5", 20440)));
    let tunnel = Tunnel::default();
    assert_eq!(connect(&paths, &tunnel, &ConnectFx), Ok(Connected::Started));
    assert!(paths.config().exists() && !visitor::required(&paths));
    assert_eq!(sync_visitor(&paths, &session).unwrap(), VisitorSync::Unsupported);
    tunnel.request_stop(&paths).unwrap();
    tunnel.release_if_stopped(&paths);

    // An XTCP host with a hand-run visitor (public entry 127.0.0.1): Connect still succeeds, the app runs no visitor.
    srv.route("/v1/config", ok("c2", &singbox_json("127.0.0.1", 20440)));
    assert_eq!(connect(&paths, &tunnel, &ConnectFx), Ok(Connected::Started));
    assert!(!visitor::required(&paths));
    tunnel.request_stop(&paths).unwrap();
    tunnel.release_if_stopped(&paths);

    // Visitor files from a newer server that was rolled back are dropped, not run against the old one.
    srv.route("/v1/xtcp-visitor", ok("v1", &visitor_json("frps-token-0123456789abcdef", 20440, "ready")));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Updated);
    assert!(visitor::required(&paths));
    srv.route("/v1/config", status(304, ""));
    srv.route("/v1/xtcp-visitor", status(404, r#"{"error":"not found"}"#));
    assert_eq!(sync_with_visitor(&paths, &session, "app").unwrap(), SyncOutcome::Unchanged);
    assert!(!visitor::required(&paths));

    // Real service errors and authentication keep their normal handling.
    srv.route("/v1/xtcp-visitor", status(500, r#"{"error":"internal server error"}"#));
    match connect(&paths, &tunnel, &ConnectFx) {
        Err(ConnectError::Configuration(m)) => assert!(m.contains("internal server error"), "{m}"),
        other => panic!("a 500 must fail Connect: {other:?}"),
    }
    srv.route("/v1/xtcp-visitor", status(503, ""));
    assert!(sync_with_visitor(&paths, &session, "app").is_err());
    srv.route("/v1/xtcp-visitor", status(401, ""));
    assert_eq!(connect(&paths, &tunnel, &ConnectFx), Err(ConnectError::SessionExpired));
    assert!(Session::load(&paths).is_none());
    fs::remove_dir_all(&paths.dir).unwrap();
}
