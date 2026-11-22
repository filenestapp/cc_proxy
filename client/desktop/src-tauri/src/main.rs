// CC Proxy desktop app: sign in, connect, see where your traffic exits.
//
// This process never runs privileged. On connect it asks the OS (one password / UAC prompt) to start the bundled
// `ccproxy tunnel` supervisor, then only writes files the supervisor reads: the sing-box config (kept current by
// polling the control plane), a heartbeat every few seconds, and a stop file on disconnect or exit.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ccproxy_core::api::{Api, Me};
use ccproxy_core::session::{Paths, Session};
use ccproxy_core::supervisor::Status;
use ccproxy_core::sync::{sync_once, SyncOutcome};
use ccproxy_core::{default_device_name, elevate, platform, DEFAULT_MODE};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT_SECS: u64 = 30;
const SYNC_EVERY: Duration = Duration::from_secs(30);

struct App {
    paths: Paths,
    want_connected: AtomicBool,
    message: Mutex<String>,
    /// Last exit IP / entry from the control plane. Local refreshes (every 1.5 s) reuse it instead of asking
    /// the server, so they must not blank it out.
    /// Keyed by session id: a reply for an earlier session never shows up under a later one.
    me: Mutex<Option<(String, Me)>>,
    /// When the user last pressed connect (seconds); older supervisor status belongs to an earlier run.
    connected_at: Mutex<u64>,
}

#[derive(Serialize)]
struct Entry {
    host: String,
    port: u16,
}

#[derive(Serialize)]
struct View {
    signed_in: bool,
    server: Option<String>,
    user: Option<String>,
    device: String,
    egress_ip: Option<String>,
    entry: Option<Entry>,
    host: Option<String>,
    /// idle | connecting | running | stopped | failed
    tunnel: String,
    tunnel_message: String,
    want_connected: bool,
    message: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn sidecar(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().map(PathBuf::from).unwrap_or_default();
    dir.join(if cfg!(windows) { format!("{name}.exe") } else { name.to_string() })
}

fn touch(path: &std::path::Path) {
    let _ = fs::write(path, now().to_string());
}

impl App {
    fn set_message(&self, m: impl Into<String>) {
        *self.message.lock().unwrap() = m.into();
    }

    fn request_stop(&self) {
        self.want_connected.store(false, Ordering::SeqCst);
        touch(&self.paths.stop());
    }

    fn view(&self, online: bool) -> View {
        let session = Session::load(&self.paths);
        let mut v = View {
            signed_in: session.is_some(),
            server: session.as_ref().map(|s| s.server.clone()),
            user: session.as_ref().map(|s| s.user.clone()),
            device: session.as_ref().map(|s| s.device.clone()).unwrap_or_else(default_device_name),
            egress_ip: None,
            entry: None,
            host: None,
            tunnel: "idle".into(),
            tunnel_message: String::new(),
            want_connected: self.want_connected.load(Ordering::SeqCst),
            message: self.message.lock().unwrap().clone(),
        };
        // The supervisor writes its status only on transitions, so an old "running" can be current. A status older
        // than the last connect belongs to a previous run (the app cannot delete it: it lives in the protected dir).
        if let Some(st) = Status::current() {
            if st.updated >= *self.connected_at.lock().unwrap() {
                v.tunnel = st.state;
                v.tunnel_message = st.message;
            }
        }
        if v.want_connected && v.tunnel != "running" && v.tunnel != "failed" {
            v.tunnel = "connecting".into();
        }
        if !v.signed_in {
            *self.me.lock().unwrap() = None;
            return v;
        }
        let session = session.expect("signed in");
        if online {
            if let Ok(api) = Api::new(&session.server) {
                let reply = api.me(&session.token);
                // Apply the reply only if this session is still the signed-in one (review finding CC-07).
                let _g = ccproxy_core::session::lock();
                if Session::is_current(&self.paths, &session.id) {
                    match reply {
                        Ok(Some(me)) => *self.me.lock().unwrap() = Some((session.id.clone(), me)),
                        Ok(None) => {
                            Session::clear_locked(&self.paths);
                            *self.me.lock().unwrap() = None;
                            v.signed_in = false;
                            v.message = "登录已失效（可能在其他地方被退出或被管理员停用），请重新登录".into();
                            return v;
                        }
                        Err(e) => v.message = format!("无法连接控制端：{e}"),
                    }
                }
            }
        }
        if let Some((id, me)) = self.me.lock().unwrap().clone() {
            if id == session.id {
                v.egress_ip = me.egress_ip;
                v.host = me.host;
                v.entry = me.entry.map(|e| Entry { host: e.host, port: e.port });
            }
        }
        v
    }
}

/// `refresh` also asks the control plane for the exit IP and entry; off the main thread so the window never stalls.
#[tauri::command]
async fn get_state(app: tauri::State<'_, Arc<App>>, refresh: bool) -> Result<View, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app.view(refresh)).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn login(app: tauri::State<'_, Arc<App>>, server: String, username: String, password: String,
               device: Option<String>) -> Result<View, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let api = Api::new(&server).map_err(|e| e.to_string())?;
        let device = device.filter(|d| !d.trim().is_empty()).unwrap_or_else(default_device_name);
        let resp = api.login(username.trim(), &password, device.trim(), platform()).map_err(|e| e.to_string())?;
        Session::new(api.base().to_string(), resp.user, resp.device, resp.token)
            .save(&app.paths)
            .map_err(|e| e.to_string())?;
        app.set_message("");
        Ok(app.view(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn logout(app: tauri::State<'_, Arc<App>>) -> Result<View, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app.request_stop();
        if let Some(s) = Session::load(&app.paths) {
            if let Ok(api) = Api::new(&s.server) {
                let _ = api.logout(&s.token);
            }
        }
        Session::clear(&app.paths);
        app.set_message("已退出登录");
        app.view(false)
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect(app: tauri::State<'_, Arc<App>>) -> Result<View, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let session = Session::load(&app.paths).ok_or("请先登录")?;
        match sync_once(&app.paths, &session, DEFAULT_MODE).map_err(|e| format!("获取配置失败：{e:#}"))? {
            SyncOutcome::SignedOut => return Err("登录已失效，请重新登录".into()),
            SyncOutcome::Unassigned(m) => return Err(format!("还没有分配出口：{m}")),
            _ => {}
        }
        let _ = fs::remove_file(app.paths.stop());
        *app.connected_at.lock().unwrap() = now();
        touch(&app.paths.heartbeat());
        app.want_connected.store(true, Ordering::SeqCst);
        let args = elevate::tunnel_args(&app.paths, &sidecar("sing-box"), HEARTBEAT_TIMEOUT_SECS);
        if let Err(e) = elevate::launch(&sidecar("ccproxy"), &args) {
            app.want_connected.store(false, Ordering::SeqCst);
            return Err(format!("没有获得管理员授权：{e:#}"));
        }
        app.set_message("");
        Ok(app.view(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn disconnect(app: tauri::State<Arc<App>>) -> View {
    app.request_stop();
    app.set_message("");
    app.view(false)
}

/// While connected: keep the heartbeat fresh and the config current.
fn background(app: Arc<App>) {
    let mut last_beat = Instant::now() - HEARTBEAT_EVERY;
    let mut last_sync = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        if !app.want_connected.load(Ordering::SeqCst) {
            continue;
        }
        if last_beat.elapsed() >= HEARTBEAT_EVERY {
            touch(&app.paths.heartbeat());
            last_beat = Instant::now();
        }
        if last_sync.elapsed() >= SYNC_EVERY {
            last_sync = Instant::now();
            if let Some(s) = Session::load(&app.paths) {
                match sync_once(&app.paths, &s, DEFAULT_MODE) {
                    Ok(SyncOutcome::SignedOut) => {
                        app.request_stop();
                        app.set_message("登录已失效（可能被管理员停用），隧道已断开");
                    }
                    Ok(SyncOutcome::Unassigned(m)) => {
                        app.request_stop();
                        app.set_message(format!("出口已被收回，隧道已断开：{m}"));
                    }
                    Ok(_) => {}
                    Err(_) => {} // offline for a moment: keep running on the current config
                }
            }
        }
    }
}

fn main() {
    let paths = Paths::new(None).expect("state directory");
    let app = Arc::new(App {
        paths,
        want_connected: AtomicBool::new(false),
        message: Mutex::new(String::new()),
        me: Mutex::new(None),
        connected_at: Mutex::new(0),
    });
    // A tunnel left over from a previous run of the app stops by itself once its heartbeat goes stale.
    {
        let app = app.clone();
        std::thread::spawn(move || background(app));
    }
    let on_exit = app.clone();
    tauri::Builder::default()
        .manage(app)
        .invoke_handler(tauri::generate_handler![get_state, login, logout, connect, disconnect])
        .build(tauri::generate_context!())
        .expect("building the app")
        .run(move |_, event| {
            if let tauri::RunEvent::Exit = event {
                on_exit.request_stop();
            }
        });
}
