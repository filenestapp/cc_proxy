//! CC-01 end to end at the supervisor: sing-box only ever sees the protected, validated copy; a tampered client
//! config is refused without touching what runs; legitimate changes reload; stop and heartbeat still work.
#![cfg(unix)]

use ccproxy_core::supervisor::{self, Options, Status};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn fixture() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/app-domains.json");
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

struct Env {
    root: PathBuf,
    user: PathBuf,
    runtime: PathBuf,
    calls: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let root = std::env::temp_dir().join(format!("ccproxy-sup-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (user, runtime) = (root.join("user"), root.join("runtime"));
        fs::create_dir_all(&user).unwrap();
        let calls = root.join("calls.log");
        // Fake sing-box: records `run` arguments and SIGHUPs; `check` always passes. It exits once the test
        // directory is gone, so a failing test (which skips the supervisor's own stop) leaves no process behind.
        let fake = root.join("sing-box");
        fs::write(&fake, format!(
            "#!/bin/sh\nif [ \"$1\" = check ]; then exit 0; fi\necho \"run $*\" >> '{c}'\ntrap 'echo HUP >> \"{c}\"' HUP\nwhile [ -d '{r}' ]; do sleep 0.05; done\n",
            c = calls.display(), r = root.display())).unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        Env { root, user, runtime, calls }
    }

    fn options(&self, heartbeat: Option<Duration>) -> Options {
        Options {
            singbox: self.root.join("sing-box"),
            client_config: self.user.join("sing-box.json"),
            stop_file: self.user.join("stop"),
            heartbeat: heartbeat.map(|d| (self.user.join("heartbeat"), d)),
            poll: Duration::from_millis(100),
            runtime_dir: self.runtime.clone(),
            require_privileged: false,
        }
    }

    fn write_client(&self, v: &Value) {
        // A new mtime each time, even within the same second.
        std::thread::sleep(Duration::from_millis(20));
        fs::write(self.user.join("sing-box.json"), serde_json::to_vec_pretty(v).unwrap()).unwrap();
        let t = std::time::SystemTime::now();
        fs::File::options().write(true).open(self.user.join("sing-box.json")).unwrap().set_modified(t).unwrap();
    }

    fn status(&self) -> Option<Status> {
        Status::read(&self.runtime.join("status.json"))
    }

    fn wait<F: Fn(&Env) -> bool>(&self, what: &str, f: F) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}; status {:?}", self.status());
    }

    fn calls(&self) -> String {
        fs::read_to_string(&self.calls).unwrap_or_default()
    }

    fn protected(&self) -> Value {
        serde_json::from_slice(&fs::read(self.runtime.join("config.json")).unwrap()).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn supervisor_runs_only_the_protected_copy_and_refuses_tampering() {
    let env = Env::new("main");
    let good = fixture();
    env.write_client(&good);
    let opts = env.options(None);
    let handle = std::thread::spawn(move || supervisor::run(opts));

    env.wait("running", |e| e.status().map(|s| s.state == "running").unwrap_or(false));
    env.wait("sing-box started", |e| e.calls().contains("run "));
    let protected_cfg = env.runtime.join("config.json");
    assert!(env.calls().contains(&format!("-c {}", protected_cfg.display())), "{}", env.calls());
    assert!(!env.calls().contains("user/sing-box.json"), "sing-box never reads the user's file");
    let cache = env.protected()["experimental"]["cache_file"]["path"].as_str().unwrap().to_string();
    assert!(cache.starts_with(&env.runtime.display().to_string()), "{cache}");
    assert_eq!(fs::metadata(&protected_cfg).unwrap().permissions().mode() & 0o777, 0o600);

    // Tampered: a root process must not follow log.output. Refused; running config untouched; no reload.
    let before = env.protected();
    let mut bad = good.clone();
    bad["log"]["output"] = Value::from("/tmp/owned-by-root");
    env.write_client(&bad);
    env.wait("rejection", |e| e.status().map(|s| s.message.contains("rejected")).unwrap_or(false));
    assert_eq!(env.protected(), before);
    assert!(!env.calls().contains("HUP"));
    assert!(!Path::new("/tmp/owned-by-root").exists());

    // A legitimate change (another rule domain) is validated, installed into the protected copy and reloaded.
    let mut spec = ccproxy_core::runtime::extract(&good).unwrap();
    spec.domains.push("new.example.net".into());
    let changed = ccproxy_core::runtime::render(&spec, None);
    env.write_client(&changed);
    env.wait("reload", |e| e.calls().contains("HUP"));
    assert!(env.protected()["dns"]["rules"][1]["domain_suffix"].to_string().contains("new.example.net"));

    // Stop file: the app's off switch.
    fs::write(env.user.join("stop"), b"").unwrap();
    handle.join().unwrap().unwrap();
    let st = env.status().unwrap();
    assert_eq!((st.state.as_str(), st.message.as_str()), ("stopped", "stopped by the app"));
}

#[test]
fn stale_heartbeat_stops_the_supervisor() {
    let env = Env::new("hb");
    env.write_client(&fixture());
    fs::write(env.user.join("heartbeat"), b"x").unwrap();
    let opts = env.options(Some(Duration::from_secs(2)));
    let handle = std::thread::spawn(move || supervisor::run(opts));
    handle.join().unwrap().unwrap();
    assert!(env.status().unwrap().message.contains("heartbeats"));
}

#[test]
fn a_tampered_config_never_starts() {
    let env = Env::new("start");
    let mut bad = fixture();
    bad["outbounds"].as_array_mut().unwrap().push(serde_json::json!({"type": "direct", "tag": "x"}));
    env.write_client(&bad);
    assert!(supervisor::run(env.options(None)).is_err());
    assert_eq!(env.status().unwrap().state, "failed");
    assert!(env.calls().is_empty(), "sing-box was never started");
}
