use super::*;

pub(crate) const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxUZXN0IFhU\nQ1AgQ0EwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAXMRUwEwYDVQQD\n-----END CERTIFICATE-----\n";

pub(crate) fn spec() -> VisitorSpec {
    VisitorSpec {
        server_addr: "frps.example.com".into(),
        server_port: 7003,
        tls_server_name: "frps.example.com".into(),
        ca_pem: CA.into(),
        auth_token: "frps-token-0123456789abcdef".into(),
        proxy_name: "ccproxy-nat-direct-20440".into(),
        secret_key: "scoped-key-0123456789abcdef_-".into(),
        bind_addr: "127.0.0.1".into(),
        bind_port: 20440,
        exit_state: "ready".into(),
    }
}

#[test]
fn rendering_carries_one_visitor_without_the_token_or_a_fallback() {
    let toml = render_toml(&spec(), Path::new("/Users/a/Library/Application Support/cc-proxy/frp-ca.pem")).unwrap();
    for want in [
        "serverAddr = \"frps.example.com\"\n",
        "serverPort = 7003\n",
        "loginFailExit = true\n",
        "auth.token = \"{{ .Envs.FRP_AUTH_TOKEN }}\"\n",
        "transport.tls.enable = true\n",
        "transport.tls.trustedCaFile = \"/Users/a/Library/Application Support/cc-proxy/frp-ca.pem\"\n",
        "transport.tls.serverName = \"frps.example.com\"\n",
        "serverName = \"ccproxy-nat-direct-20440\"\n",
        "secretKey = \"scoped-key-0123456789abcdef_-\"\n",
        "bindAddr = \"127.0.0.1\"\n",
        "bindPort = 20440\n",
        "protocol = \"quic\"\n",
        "keepTunnelOpen = true\n",
        "maxRetriesAnHour = 8\n",
    ] {
        assert!(toml.contains(want), "missing {want:?} in\n{toml}");
    }
    assert!(!toml.contains("frps-token-0123456789abcdef"), "the token must stay out of the file");
    let settings: String = toml.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>().join("\n");
    assert!(!settings.to_ascii_lowercase().contains("fallback"), "no relay fallback");
    assert_eq!(toml.matches("{{").count(), 1, "the token template is the only template action");
    assert_eq!(toml.matches("[[visitors]]").count(), 1);
}

#[test]
fn windows_and_unusual_paths_are_escaped_and_template_actions_refused() {
    let toml = render_toml(&spec(), Path::new(r"C:\Users\Jo O'Neil\AppData\Roaming\cc-proxy\frp-ca.pem")).unwrap();
    assert!(toml.contains(r#"transport.tls.trustedCaFile = "C:\\Users\\Jo O'Neil\\AppData\\Roaming\\cc-proxy\\frp-ca.pem""#), "{toml}");
    let toml = render_toml(&spec(), Path::new("/home/a \"b\"/frp-ca.pem")).unwrap();
    assert!(toml.contains(r#"trustedCaFile = "/home/a \"b\"/frp-ca.pem""#), "{toml}");
    assert!(render_toml(&spec(), Path::new("/home/{{.Envs.HOME}}/frp-ca.pem")).is_err());
}

#[test]
fn every_field_is_validated_before_it_reaches_frpc() {
    type Mutate = fn(&mut VisitorSpec);
    let bad: &[(&str, Mutate)] = &[
        ("server_addr quote", |s| s.server_addr = "frps\".example".into()),
        ("server_addr template", |s| s.server_addr = "{{.Envs.X}}".into()),
        ("server_addr empty", |s| s.server_addr.clear()),
        ("server_port zero", |s| s.server_port = 0),
        ("tls name newline", |s| s.tls_server_name = "a\nb".into()),
        ("ca not pem", |s| s.ca_pem = "hello".into()),
        ("ca with template", |s| s.ca_pem = CA.replace("MIIB", "{{x}}")),
        ("token short", |s| s.auth_token = "short".into()),
        ("token template", |s| s.auth_token = "{{ .Envs.HOME }}0123456789".into()),
        ("token quote", |s| s.auth_token = "abc\"defghijklmnopq".into()),
        ("secret space", |s| s.secret_key = "abc defghijklmnopqrs".into()),
        ("proxy name slash", |s| s.proxy_name = "a/b".into()),
        ("bind addr", |s| s.bind_addr = "0.0.0.0".into()),
        ("bind port zero", |s| s.bind_port = 0),
    ];
    for (what, mutate) in bad {
        let mut s = spec();
        mutate(&mut s);
        assert!(s.validate().is_err(), "{what} was accepted");
        assert!(render_toml(&s, Path::new("/tmp/frp-ca.pem")).is_err(), "{what} was rendered");
    }
    spec().validate().unwrap();
}

#[test]
fn frpc_log_lines_are_classified() {
    // Shapes of frpc 0.72.0 console lines (log.to = console, level info).
    let cases: &[(&str, Option<Event>)] = &[
        ("2026-11-25 10:00:01.123 [I] [client/visitor/visitor_manager.go:135] [7f3c] start visitor success",
         Some(Event::Listening)),
        ("2026-11-25 10:00:03.456 [I] [client/visitor/xtcp.go:312] [7f3c] [ccproxy-nat-direct-20440-visitor] establishing nat hole connection successful, sid [1764036003], remoteAddr [203.0.113.9:41000]",
         Some(Event::Ready)),
        ("2026-11-25 10:00:01.000 [W] [client/visitor/visitor_manager.go:132] [7f3c] start error: listen tcp 127.0.0.1:20440: bind: address already in use",
         Some(Event::Fatal(Reason::LocalPortBusy, "listen tcp 127.0.0.1:20440: bind: address already in use".into()))),
        ("2026-11-25 10:00:01.000 [W] [client/visitor/visitor_manager.go:132] [7f3c] start error: listen tcp 127.0.0.1:20440: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.",
         Some(Event::Fatal(Reason::LocalPortBusy, "listen tcp 127.0.0.1:20440: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted".into()))),
        ("2026-11-25 10:00:00.500 [W] [client/service.go:380] connect to server error: token in login doesn't match token from configuration",
         Some(Event::Fatal(Reason::TokenRefused, "token in login doesn't match token from configuration".into()))),
        ("login to the server failed: tls: failed to verify certificate: x509: certificate signed by unknown authority. With loginFailExit enabled, no additional retries will be attempted",
         Some(Event::Fatal(Reason::CertificateRejected, "tls: failed to verify certificate: x509: certificate signed by unknown authority".into()))),
        ("2026-11-25 10:00:00.500 [W] [client/service.go:380] connect to server error: dial tcp 198.51.100.10:7003: connect: connection refused",
         Some(Event::Fatal(Reason::ServerUnreachable, "dial tcp 198.51.100.10:7003: connect: connection refused".into()))),
        ("2026-11-25 10:00:00.500 [W] [client/service.go:380] connect to server error: dial tcp: lookup frps.example.com: no such host",
         Some(Event::Fatal(Reason::ServerUnreachable, "dial tcp: lookup frps.example.com: no such host".into()))),
        ("2026-11-25 10:00:05.000 [W] [client/visitor/xtcp.go:297] [7f3c] [v] nathole exchange info error: xtcp server for [ccproxy-nat-direct-20440] doesn't exist",
         Some(Event::PunchFailed(Reason::ExitNotOnline, "xtcp server for [ccproxy-nat-direct-20440] doesn't exist".into()))),
        ("2026-11-25 10:00:05.000 [W] [client/visitor/xtcp.go:308] [7f3c] [v] make hole error: wait detect message timeout",
         Some(Event::PunchFailed(Reason::HolePunchFailed, "wait detect message timeout".into()))),
        ("2026-11-25 10:01:35.000 [W] [client/visitor/xtcp.go:127] [7f3c] [v] keepTunnelOpenWorker get tunnel connection error: open tunnel timeout",
         Some(Event::PunchFailed(Reason::HolePunchFailed, "open tunnel timeout".into()))),
        ("2026-11-25 10:00:00.400 [I] [client/service.go:389] [7f3c] login to server success, get run id [7f3c]", None),
        ("2026-11-25 10:00:00.300 [I] [client/service.go:369] try to connect to server...", None),
    ];
    for (line, want) in cases {
        assert_eq!(&classify(line), want, "{line}");
    }
}

#[test]
fn each_failure_has_its_own_message() {
    let reasons = [Reason::ServerUnreachable, Reason::TokenRefused, Reason::CertificateRejected, Reason::ExitNotOnline,
                   Reason::HolePunchFailed, Reason::LocalPortBusy, Reason::FrpcExited, Reason::FrpcMissing];
    let messages: Vec<String> = reasons.iter().map(|r| r.message("", 20440)).collect();
    for (i, m) in messages.iter().enumerate() {
        assert!(!m.is_empty());
        assert_eq!(messages.iter().filter(|o| *o == m).count(), 1, "{m} is not distinct");
        assert!(!messages[i].contains("()"));
    }
    assert!(Reason::LocalPortBusy.message("", 20440).contains("20440"));
    assert!(Reason::HolePunchFailed.message("", 0).contains("never relayed"));
}

fn state(tag: &str) -> Paths {
    let d = std::env::temp_dir().join(format!("ccproxy-visitor-unit-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    Paths::new(Some(d)).unwrap()
}

#[test]
fn the_tunnel_counts_as_connected_only_when_the_visitor_is_ready() {
    const GUARD: u32 = 4242;
    let paths = state("view");
    assert_eq!(tunnel_view(&paths, Some(GUARD)), None, "no visitor configured");
    let mut s = spec();
    s.exit_state = "pending".into();
    write_files(&paths, &s).unwrap();
    let fp = fingerprint(&paths).unwrap();
    let (state, msg) = tunnel_view(&paths, Some(GUARD)).unwrap();
    assert_eq!(state, "connecting");
    assert!(msg.contains("Starting") && msg.contains("(pending)"), "{msg}");

    let put = |st: &str, reason: Option<Reason>, message: &str, fp: &str, guard: u32| {
        let v = VisitorStatus { state: st.into(), reason, message: message.into(), updated: 1, fingerprint: fp.into(), guard, route_key: None };
        fs::write(paths.visitor_status(), serde_json::to_vec(&v).unwrap()).unwrap();
    };
    put("listening", None, "", &fp, GUARD);
    assert_eq!(tunnel_view(&paths, Some(GUARD)).unwrap().0, "connecting");
    put("ready", None, "", &fp, GUARD);
    assert_eq!(tunnel_view(&paths, Some(GUARD)).unwrap(), ("running".into(), String::new()));
    put("ready", None, "", "an-older-configuration", GUARD);
    assert_eq!(tunnel_view(&paths, Some(GUARD)).unwrap().0, "connecting", "a status for another configuration does not count");
    let busy = Reason::LocalPortBusy.message("", 20440);
    put("failed", Some(Reason::LocalPortBusy), &busy, &fp, GUARD);
    assert_eq!(tunnel_view(&paths, Some(GUARD)).unwrap(), ("failed".into(), busy));
    put("stopped", None, "", &fp, GUARD);
    assert_eq!(tunnel_view(&paths, Some(GUARD)).unwrap().0, "failed");
    fs::remove_dir_all(&paths.dir).unwrap();
}

/// PR #64 e2e: a fresh connection must not report connected from the "ready" status a previous connection left
/// behind for the same configuration (its guard was killed before it could write "stopped").
#[test]
fn a_stale_ready_status_does_not_count_for_a_fresh_connection() {
    let paths = state("stale-ready");
    write_files(&paths, &spec()).unwrap();
    let stale = VisitorStatus { state: "ready".into(), reason: None, message: String::new(), updated: 1,
                                fingerprint: fingerprint(&paths).unwrap(), guard: 1111, route_key: None };
    fs::write(paths.visitor_status(), serde_json::to_vec(&stale).unwrap()).unwrap();
    // No guard of its own yet (the TUN is not up, or the guard has not started).
    assert_eq!(tunnel_view(&paths, None).unwrap().0, "connecting");
    // Its own guard started but has written nothing yet.
    assert_eq!(tunnel_view(&paths, Some(2222)).unwrap().0, "connecting");
    // Only the guard that wrote it can make it count.
    assert_eq!(tunnel_view(&paths, Some(1111)).unwrap().0, "running");
    // A status file from a build without the guard field never counts.
    let legacy = serde_json::json!({"state": "ready", "message": "", "updated": 1, "fingerprint": fingerprint(&paths).unwrap()});
    fs::write(paths.visitor_status(), legacy.to_string()).unwrap();
    assert_eq!(tunnel_view(&paths, Some(2222)).unwrap().0, "connecting");
    fs::remove_dir_all(&paths.dir).unwrap();
}

#[test]
fn visitor_files_are_private_and_the_info_file_holds_no_credentials() {
    let paths = state("files");
    write_files(&paths, &spec()).unwrap();
    for p in [paths.visitor_toml(), paths.visitor_ca(), paths.visitor_token(), paths.visitor_info()] {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
        }
        assert!(p.exists());
    }
    assert_eq!(fs::read_to_string(paths.visitor_token()).unwrap(), "frps-token-0123456789abcdef");
    let info = fs::read_to_string(paths.visitor_info()).unwrap();
    assert!(!info.contains("frps-token") && !info.contains("scoped-key"), "{info}");
    // An unchanged spec leaves the files (and the fingerprint the guard runs) alone; a rotated token changes it.
    let fp = fingerprint(&paths).unwrap();
    write_files(&paths, &spec()).unwrap();
    assert_eq!(fingerprint(&paths).unwrap(), fp);
    let mut rotated = spec();
    rotated.auth_token = "frps-token-rotated-0123456789".into();
    write_files(&paths, &rotated).unwrap();
    assert_ne!(fingerprint(&paths).unwrap(), fp);
    // Removing them with the session.
    Session::new("http://x".into(), "u".into(), "d".into(), "t".into()).save(&paths).unwrap();
    write_files(&paths, &spec()).unwrap();
    Session::clear(&paths).unwrap();
    for p in files(&paths) {
        assert!(!p.exists(), "{} survived sign-out", p.display());
    }
    fs::remove_dir_all(&paths.dir).unwrap();
}
