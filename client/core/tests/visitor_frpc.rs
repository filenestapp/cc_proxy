//! The visitor configuration the app renders is accepted by the real frpc (set FRPC_TEST_BIN, as for the control
//! plane's frpc tests; `scripts/fetch-binaries.sh` leaves the pinned one in desktop/src-tauri/binaries).

use ccproxy_core::visitor::{render_toml, VisitorSpec};
use std::fs;
use std::process::Command;

#[test]
fn real_frpc_accepts_the_rendered_visitor() {
    let Ok(bin) = std::env::var("FRPC_TEST_BIN") else {
        eprintln!("skipped: set FRPC_TEST_BIN to an frpc binary");
        return;
    };
    let dir = std::env::temp_dir().join(format!("ccproxy-frpc-verify-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    // A directory name with a space and a quote, as user profile paths can have.
    let state = dir.join("Jo O'Neil \"x\"");
    fs::create_dir_all(&state).unwrap();
    let ca = state.join("frp-ca.pem");
    let pem = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "/dev/null",
               "-days", "1", "-subj", "/CN=frpc verify CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        .output()
        .expect("openssl");
    let pem = String::from_utf8(pem.stdout).unwrap();
    fs::write(&ca, &pem).unwrap();
    let spec = VisitorSpec {
        server_addr: "frps.example.com".into(),
        server_port: 7003,
        tls_server_name: "frps.example.com".into(),
        ca_pem: pem,
        auth_token: "frps-token-0123456789abcdef".into(),
        proxy_name: "ccproxy-nat-direct-20440".into(),
        secret_key: "scoped-key-0123456789abcdef".into(),
        bind_addr: "127.0.0.1".into(),
        bind_port: 20440,
        exit_state: "ready".into(),
    };
    let conf = state.join("frpc-visitor.toml");
    fs::write(&conf, render_toml(&spec, &ca).unwrap()).unwrap();
    let out = Command::new(&bin).arg("verify").arg("-c").arg(&conf)
        .env("FRP_AUTH_TOKEN", &spec.auth_token).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("syntax is ok"), "frpc verify: {text}");
    fs::remove_dir_all(&dir).unwrap();
}
