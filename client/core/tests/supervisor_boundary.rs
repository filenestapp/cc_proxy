//! CC-01 end to end at the supervisor: sing-box only ever sees the protected, validated copy; a tampered client
//! config is refused without touching what runs; legitimate changes reload; stop and heartbeat still work.
#![cfg(unix)]

use ccproxy_core::runtime;
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
            bundled_frpc: None,
            client_config: self.user.join("sing-box.json"),
            stop_file: self.user.join("stop"),
            heartbeat: heartbeat.map(|d| (self.user.join("heartbeat"), d)),
            connection_id: None,
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

#[test]
fn only_the_protected_xtcp_config_exempts_bundled_frpc_stun() {
    let env = Env::new("xtcp-stun");
    let frpc = env.root.join("frpc");
    let public = fixture();
    let mut xtcp = public.clone();
    xtcp["outbounds"][0]["server"] = serde_json::json!("127.0.0.1");
    let bypass = serde_json::json!({
        "ip_version": 4, "network": "udp", "protocol": "stun", "process_path": [frpc], "outbound": "direct",
    });
    let mut opts = env.options(None);
    opts.bundled_frpc = Some(frpc);
    env.write_client(&public);
    let handle = std::thread::spawn(move || supervisor::run(opts));
    env.wait("public route", |e| e.status().is_some_and(|s| s.state == "running"));
    assert_eq!(env.protected()["route"]["rules"], public["route"]["rules"]);

    env.write_client(&xtcp);
    env.wait("protected XTCP route", |e| e.status().is_some_and(|s| s.route_generation == 2));
    let protected = env.protected();
    assert_eq!(protected["route"]["rules"][2], bypass);
    assert_eq!(protected["route"]["rules"][3], xtcp["route"]["rules"][2]);

    xtcp["route"]["rules"].as_array_mut().unwrap().insert(2, bypass);
    env.write_client(&xtcp);
    env.wait("injected bypass rejected", |e| e.status().is_some_and(|s| s.message.contains("rejected")));
    assert_eq!(env.protected(), protected);
    assert_eq!(env.status().unwrap().route_generation, 2);

    fs::write(env.user.join("stop"), b"").unwrap();
    handle.join().unwrap().unwrap();
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_delayed_supervisor_cannot_start_for_a_replaced_connection() {
    let env = Env::new("replaced-connection");
    env.write_client(&fixture());
    fs::write(env.user.join("connection-id"), "new").unwrap();
    let mut options = env.options(None);
    options.connection_id = Some("old".into());

    supervisor::run(options).unwrap();

    let status = env.status().unwrap();
    assert_eq!(status.state, "stopped");
    assert_eq!(status.connection_id.as_deref(), Some("old"));
    assert!(env.calls().is_empty());
}

#[test]
fn an_exiting_sing_box_is_never_reported_as_ready() {
    let env = Env::new("unready-child");
    env.write_client(&fixture());
    let options = env.options(None);
    fs::write(&options.singbox, format!(
        "#!/bin/sh\n[ \"$1\" = check ] && exit 0\nprintf 'start\\n' >> '{}'\nexit 1\n",
        env.calls.display(),
    )).unwrap();
    let worker = std::thread::spawn(move || supervisor::run(options));

    env.wait("a retry after sing-box exits", |env| {
        assert!(!env.status().is_some_and(|status| status.state == "running"));
        env.calls().lines().count() >= 2
    });
    fs::write(env.user.join("stop"), b"").unwrap();
    worker.join().unwrap().unwrap();
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
    let original_exit = env.status().unwrap().egress_fingerprint.unwrap();
    let probe = runtime::render_exit_probe(&serde_json::to_vec(&good).unwrap(), &original_exit).unwrap();
    assert_eq!(probe["outbounds"], serde_json::json!([good["outbounds"][0]]));
    assert!(probe.get("inbounds").is_none());
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
    assert_eq!(env.status().unwrap().egress_fingerprint.as_deref(), Some(original_exit.as_str()));

    let mut missing_stun = good.clone();
    missing_stun["route"]["rules"].as_array_mut().unwrap().remove(2);
    let route = env.status().unwrap().running_route();
    env.write_client(&missing_stun);
    env.wait("STUN rule rejection", |e| {
        e.status().is_some_and(|s| s.state == "running" && s.message.contains("expected the UDP STUN rule"))
    });
    assert_eq!(env.protected(), before);
    assert_eq!(env.status().unwrap().running_route(), route);
    assert!(!env.calls().contains("HUP"));

    // A valid policy and exit change is applied before probes can use the new exit.
    let mut spec = ccproxy_core::runtime::extract(&good).unwrap();
    spec.domains.push("new.example.net".into());
    spec.server_port += 1;
    let changed = ccproxy_core::runtime::render(&spec, None);
    assert!(runtime::render_exit_probe(&serde_json::to_vec(&changed).unwrap(), &original_exit).is_err());
    env.write_client(&changed);
    env.wait("reload", |e| e.calls().contains("HUP"));
    assert!(env.protected()["dns"]["rules"][1]["domain_suffix"].to_string().contains("new.example.net"));
    env.wait("active exit updated", |e| e.status().is_some_and(|s| s.message == "config reloaded"));
    let new_exit = env.status().unwrap().egress_fingerprint.unwrap();
    assert_ne!(new_exit, original_exit);
    assert!(runtime::render_exit_probe(&serde_json::to_vec(&good).unwrap(), &new_exit).is_err());
    assert!(runtime::render_exit_probe(&serde_json::to_vec(&changed).unwrap(), &new_exit).is_ok());

    // Stop file: the app's off switch.
    fs::write(env.user.join("stop"), b"").unwrap();
    handle.join().unwrap().unwrap();
    let st = env.status().unwrap();
    assert_eq!((st.state.as_str(), st.message.as_str()), ("stopped", "stopped by the app"));
    assert!(st.egress_fingerprint.is_none());
}

#[test]
fn runtime_dir_is_rechecked_before_each_privileged_write() {
    let env = Env::new("swap");
    let good = fixture();
    env.write_client(&good);
    let opts = env.options(None);
    let handle = std::thread::spawn(move || supervisor::run(opts));
    env.wait("running", |e| e.status().map(|s| s.state == "running").unwrap_or(false));

    // The runtime directory is replaced by a link to somewhere else; a reload must not write through it.
    let elsewhere = env.root.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::rename(&env.runtime, env.root.join("runtime.old")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &env.runtime).unwrap();
    let mut spec = ccproxy_core::runtime::extract(&good).unwrap();
    spec.domains.push("new.example.net".into());
    env.write_client(&ccproxy_core::runtime::render(&spec, None));
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing written through the link");
    assert!(!env.calls().contains("HUP"), "no reload");

    // Stop still works.
    fs::write(env.user.join("stop"), b"").unwrap();
    handle.join().unwrap().unwrap();
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
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

#[test]
fn entries_left_in_the_runtime_dir_are_replaced_not_followed() {
    use std::os::unix::fs::{symlink, MetadataExt};
    let env = Env::new("upgrade");
    let outside = env.root.join("outside");
    fs::write(&outside, b"keep").unwrap();
    // What an older version's runtime directory may hold, each pointing at a file outside it.
    fs::create_dir_all(env.runtime.join("work")).unwrap();
    symlink(&outside, env.runtime.join("tunnel.log")).unwrap();
    symlink(&outside, env.runtime.join("candidate.tmp")).unwrap();
    symlink(&outside, env.runtime.join("config.json")).unwrap();
    symlink(&outside, env.runtime.join("work/cache.db")).unwrap();
    fs::hard_link(&outside, env.runtime.join("status.json")).unwrap();

    let good = fixture();
    env.write_client(&good);
    let opts = env.options(None);
    let handle = std::thread::spawn(move || supervisor::run(opts));
    env.wait("running", |e| e.status().map(|s| s.state == "running").unwrap_or(false));
    env.wait("sing-box started", |e| e.calls().contains("run "));

    let mut spec = ccproxy_core::runtime::extract(&good).unwrap();
    spec.domains.push("new.example.net".into());
    env.write_client(&ccproxy_core::runtime::render(&spec, None));
    env.wait("reload", |e| e.calls().contains("HUP"));
    fs::write(env.user.join("stop"), b"").unwrap();
    handle.join().unwrap().unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"keep", "nothing written through the old entries");
    assert_eq!(fs::metadata(&outside).unwrap().nlink(), 1);
    for name in ["tunnel.log", "config.json", "status.json"] {
        let m = fs::symlink_metadata(env.runtime.join(name)).unwrap();
        assert!(m.file_type().is_file() && m.nlink() == 1, "{name} is a plain file now");
    }
    assert!(fs::symlink_metadata(env.runtime.join("work/cache.db")).is_err(), "unsafe cache removed");
    assert_eq!(env.status().unwrap().message, "stopped by the app");
}

#[test]
fn a_linked_work_dir_fails_closed() {
    let env = Env::new("workdir");
    let elsewhere = env.root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(&env.runtime).unwrap();
    std::os::unix::fs::symlink(&elsewhere, env.runtime.join("work")).unwrap();
    env.write_client(&fixture());
    assert!(supervisor::run(env.options(None)).is_err());
    assert!(env.calls().is_empty(), "sing-box was never started");
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}
