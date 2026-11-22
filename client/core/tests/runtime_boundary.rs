//! CC-01: what crosses the privilege boundary. The supervisor must accept exactly what the control plane's
//! gen.py produces for mode=app (fixtures from tests/fixtures/regen.py) and refuse anything else.

use ccproxy_core::runtime::{accept, extract, prepare_protected_dir, read_client_config, render};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(format!("{name}.json"));
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

const FIXTURES: &[&str] = &["app-domains", "app-processes", "app-local-dns", "app-ipv6-dns"];

#[test]
fn every_gen_py_client_config_round_trips() {
    for name in FIXTURES {
        let v = fixture(name);
        let spec = extract(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(render(&spec, None), v, "{name}");
    }
}

#[test]
fn accepted_config_gets_the_supervisors_cache_path_and_nothing_else_changes() {
    let v = fixture("app-domains");
    let (_, protected) = accept(&serde_json::to_vec(&v).unwrap(), Path::new("/protected/cache.db")).unwrap();
    assert_eq!(protected["experimental"]["cache_file"]["path"], "/protected/cache.db");
    let mut without = protected.clone();
    without["experimental"]["cache_file"].as_object_mut().unwrap().remove("path");
    assert_eq!(without, v);
}

fn rejected(mutate: impl Fn(&mut Value)) -> String {
    let mut v = fixture("app-processes");
    mutate(&mut v);
    match accept(&serde_json::to_vec(&v).unwrap(), Path::new("/protected/cache.db")) {
        Ok(_) => panic!("accepted a tampered config: {v}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn unexpected_fields_and_values_are_refused() {
    // Things a root process must never be talked into.
    rejected(|v| v["log"]["output"] = json!("/etc/sudoers"));
    rejected(|v| v["experimental"]["cache_file"]["path"] = json!("/etc/passwd"));
    rejected(|v| v["experimental"]["clash_api"] = json!({"external_controller": "0.0.0.0:9090"}));
    rejected(|v| v["outbounds"].as_array_mut().unwrap().push(json!({"type": "socks", "tag": "x", "server": "evil", "server_port": 1})));
    rejected(|v| v["inbounds"].as_array_mut().unwrap().push(json!({"type": "mixed", "listen": "0.0.0.0", "listen_port": 1080})));
    rejected(|v| v["inbounds"][0]["address"] = json!(["10.0.0.1/8"]));
    rejected(|v| v["route"]["rules"].as_array_mut().unwrap().push(json!({"ip_cidr": ["0.0.0.0/0"], "outbound": "egress"})));
    rejected(|v| v["route"]["final"] = json!("egress"));
    rejected(|v| v["outbounds"][0]["tls"]["insecure"] = json!(true));
    // Malformed parameters.
    rejected(|v| v["outbounds"][0]["uuid"] = json!("not-a-uuid"));
    rejected(|v| v["outbounds"][0]["server"] = json!("evil host"));
    rejected(|v| v["outbounds"][0]["tls"]["reality"]["public_key"] = json!("short"));
    rejected(|v| v["outbounds"][0]["tls"]["utls"]["fingerprint"] = json!("custom"));
    rejected(|v| v["dns"]["servers"][1] = json!({"type": "udp", "tag": "direct-dns", "server": "dns.example.com"}));
    rejected(|v| v["dns"]["servers"][1] = json!({"type": "https", "tag": "direct-dns", "server": "1.1.1.1"}));
    let msg = rejected(|v| {
        for path in ["/dns/rules/0/domain_suffix", "/dns/rules/1/domain_suffix", "/route/rules/2/domain_suffix"] {
            *v.pointer_mut(path).unwrap() = json!(["../../etc/resolver"]);
        }
    });
    assert!(msg.contains("rule domain"), "{msg}");
    rejected(|v| {
        for rule in v["route"]["rules"].as_array_mut().unwrap() {
            if rule.get("process_name").is_some() {
                rule["process_name"] = json!(["bad\u{0}name"]);
            }
        }
    });
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ccproxy-rt-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn client_config_must_be_a_regular_small_file() {
    let d = tmpdir("read");
    let cfg = d.join("sing-box.json");
    fs::write(&cfg, b"{}").unwrap();
    assert!(read_client_config(&cfg).is_ok());
    #[cfg(unix)]
    {
        let link = d.join("link.json");
        std::os::unix::fs::symlink(&cfg, &link).unwrap();
        assert!(read_client_config(&link).is_err(), "symlinks are refused");
    }
    fs::write(&cfg, vec![b' '; (1 << 20) + 1]).unwrap();
    assert!(read_client_config(&cfg).is_err(), "oversized files are refused");
    fs::remove_dir_all(&d).unwrap();
}

#[cfg(unix)]
#[test]
fn protected_dir_rejects_links_and_unprivileged_ownership() {
    let d = tmpdir("prot");
    let target = d.join("real");
    fs::create_dir(&target).unwrap();
    let link = d.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(prepare_protected_dir(&link, false).is_err(), "a symlinked runtime dir is refused");
    let fresh = d.join("fresh");
    prepare_protected_dir(&fresh, false).unwrap();
    assert!(fresh.is_dir());
    // Owned by the (non-root) test user, so the privileged check refuses it.
    if unsafe { libc_geteuid() } != 0 {
        assert!(prepare_protected_dir(&fresh, true).is_err());
    }
    fs::remove_dir_all(&d).unwrap();
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}
