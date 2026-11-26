// aifree desktop app: sign in, connect, see where your traffic exits.
//
// This process never runs privileged. On connect it asks the OS (one password / UAC prompt) to start the bundled
// `aifree tunnel` supervisor, then only writes files the supervisor reads: the sing-box config (kept current by
// polling the control plane), a heartbeat every few seconds, and a stop file on disconnect or exit.
//
// When the exit host uses XTCP, the app also runs the bundled frpc as the visitor, unprivileged, through the
// `aifree visitor` guard (ccproxy_core::visitor): started once the supervisor reports the TUN running, and the tunnel
// counts as connected only when the visitor listens and the first direct path is open. It stops on disconnect,
// sign-out, exit and when the app dies (the guard sees its stdin close).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod exit_probe;
mod netcheck;
mod tray;
mod updates;

use anyhow::Result;
use ccproxy_core::api::{Api, LoginError};
use ccproxy_core::commands::{self, touch, ConnectError, Connected, Effects, LoggedOut, Tunnel, HEARTBEAT_TIMEOUT_SECS};
use ccproxy_core::session::{Paths, Session};
use ccproxy_core::supervisor::Status;
use ccproxy_core::sync::{sync_with_visitor, SyncOutcome};
use ccproxy_core::visitor::{self, Launcher, VisitorProcess};
use ccproxy_core::{control_plane_url, default_device_name, elevate, platform, DEFAULT_MODE};
use exit_probe::{Observation, PublicExit};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Manager;

const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);
const SYNC_EVERY: Duration = Duration::from_secs(30);

struct App {
    paths: Paths,
    sign_in_server: String,
    /// Whether this process owns the shared client connection.
    tunnel: Tunnel,
    message: Mutex<Option<AppMessage>>,
    /// Last assignment check from the control plane, keyed by session id.
    assignment: Mutex<Option<(String, bool)>>,
    exit_observation: Mutex<Option<Observation>>,
    tray_language: Mutex<tray::Language>,
    /// The XTCP visitor guard, when the exit host needs one.
    visitor: Mutex<VisitorProcess>,
}

/// The real effects behind the connect and logout commands (see [`commands`]).
struct DesktopEffects;

impl Effects for DesktopEffects {
    fn sync(&self, paths: &Paths, session: &Session) -> Result<SyncOutcome> {
        sync_with_visitor(paths, session, DEFAULT_MODE)
    }

    fn launch_supervisor(&self, paths: &Paths, connection_id: &str) -> Result<()> {
        let args = elevate::tunnel_args(paths, &sidecar("sing-box"), HEARTBEAT_TIMEOUT_SECS, connection_id);
        elevate::launch(&sidecar("aifree"), &args)
    }

    fn remote_logout(&self, session: &Session) -> Result<()> {
        Api::new(&session.server)?.logout(&session.token)
    }
}

// The webview translates message keys. Native and server diagnostics stay available as details.
#[derive(Clone, Serialize)]
#[serde(tag = "key", content = "detail", rename_all = "snake_case")]
enum AppMessage {
    InvalidServer,
    IncorrectCredentials,
    TooManySignInAttempts,
    SignInRejected(String),
    ControlPlaneUnreachable(String),
    SessionSaveFailed(String),
    OperationFailed(String),
    SignInRequired,
    SessionExpired,
    SessionChangedWhileConnecting,
    SessionExpiredDisconnected,
    NoEgressAssigned(String),
    EgressRevoked(String),
    ConfigurationUnavailable(String),
    AuthorizationUnavailable(String),
    XtcpUnavailable(String),
    SignedOut,
}

impl From<LoginError> for AppMessage {
    fn from(error: LoginError) -> Self {
        match error {
            LoginError::WrongCredentials => Self::IncorrectCredentials,
            LoginError::TooManyAttempts => Self::TooManySignInAttempts,
            LoginError::Rejected(detail) => Self::SignInRejected(detail),
            LoginError::Network(detail) => Self::ControlPlaneUnreachable(detail),
        }
    }
}

impl From<ConnectError> for AppMessage {
    fn from(error: ConnectError) -> Self {
        match error {
            ConnectError::SignInRequired => Self::SignInRequired,
            ConnectError::SessionExpired => Self::SessionExpired,
            ConnectError::Unassigned(detail) => Self::NoEgressAssigned(detail),
            ConnectError::Configuration(detail) => Self::ConfigurationUnavailable(detail),
            ConnectError::Authorization(detail) => Self::AuthorizationUnavailable(detail),
            ConnectError::Xtcp(detail) => Self::XtcpUnavailable(detail),
            ConnectError::Busy | ConnectError::Canceled => Self::OperationFailed(error.to_string()),
        }
    }
}

#[derive(Serialize)]
struct View {
    signed_in: bool,
    login_username: Option<String>,
    device: String,
    has_assignment: bool,
    public_exit: PublicExit,
    /// idle | connecting | running | stopped | failed
    tunnel: String,
    tunnel_message: String,
    want_connected: bool,
    message: Option<AppMessage>,
}

fn launcher() -> Launcher {
    Launcher { cli: sidecar("aifree"), frpc: sidecar("frpc") }
}

fn sidecar(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().map(PathBuf::from).unwrap_or_default();
    dir.join(if cfg!(windows) { format!("{name}.exe") } else { name.to_string() })
}

impl App {
    fn set_message(&self, message: Option<AppMessage>) {
        *self.message.lock().unwrap() = message;
    }

    fn request_stop(&self) -> Result<()> {
        self.tunnel.request_stop(&self.paths)?;
        self.visitor.lock().unwrap().stop();
        *self.exit_observation.lock().unwrap() = None;
        Ok(())
    }

    fn current_status(&self) -> Option<Status> {
        Status::for_paths(&self.paths)
    }

    fn view(&self, online: bool) -> View {
        let session = Session::load(&self.paths);
        let mut v = View {
            signed_in: session.is_some(),
            login_username: session.as_ref().map(|s| s.login_username.as_ref().unwrap_or(&s.user).clone()),
            device: session.as_ref().map(|s| s.device.clone()).unwrap_or_else(default_device_name),
            has_assignment: false,
            public_exit: PublicExit::NotConnected,
            tunnel: "idle".into(),
            tunnel_message: String::new(),
            want_connected: false,
            message: self.message.lock().unwrap().clone(),
        };
        if !v.signed_in {
            return v;
        }
        let session = session.expect("signed in");
        if online {
            if let Ok(api) = Api::new(&session.server) {
                let reply = api.me(&session.token);
                // Apply the reply only if this session is still the signed-in one (review finding CC-07).
                let Ok(_g) = ccproxy_core::session::lock(&self.paths) else {
                    v.message = Some(AppMessage::OperationFailed("Could not lock the device session.".into()));
                    return v;
                };
                if Session::is_current(&self.paths, &session.id) {
                    match reply {
                        Ok(Some(me)) => {
                            *self.assignment.lock().unwrap() = Some((session.id.clone(), me.entry.is_some()));
                            if let Some(username) = me.login_username.filter(|_| session.login_username.is_none()) {
                                if let Err(error) = session.save_login_username_locked(&self.paths, username.clone()) {
                                    eprintln!("Could not save the login username: {error}");
                                }
                                v.login_username = Some(username);
                            }
                        }
                        Ok(None) => {
                            Session::clear_locked(&self.paths);
                            *self.assignment.lock().unwrap() = None;
                            v.signed_in = false;
                            v.message = Some(AppMessage::SessionExpired);
                            return v;
                        }
                        Err(e) => v.message = Some(AppMessage::ControlPlaneUnreachable(e.to_string())),
                    }
                }
            }
        }
        v.has_assignment = self.assignment.lock().unwrap().as_ref()
            .is_some_and(|(id, assigned)| id == &session.id && *assigned);
        let status = self.current_status();
        v.want_connected = commands::connection_requested(&self.paths, status.as_ref());
        if let Some(status) = status {
            v.tunnel = status.state.clone();
            v.tunnel_message = status.message.clone();
            // On an XTCP exit the tunnel is connected only once the visitor is ready.
            if v.want_connected && status.state == "running" {
                if let Some((state, message)) = visitor::tunnel_view(&self.paths, visitor::guard_for_route(&self.paths, &status)) {
                    v.tunnel = state;
                    v.tunnel_message = message;
                }
            }
            if v.want_connected && v.tunnel == "running" {
                v.public_exit = exit_probe::display(self, &session, &status);
            }
        }
        if v.want_connected && v.tunnel != "running" && v.tunnel != "failed" {
            v.tunnel = "connecting".into();
        }
        v
    }
}

#[tauri::command]
fn system_languages() -> Vec<String> {
    sys_locale::get_locales().collect()
}

#[tauri::command]
fn set_tray_language(app: tauri::State<'_, Arc<App>>, language: tray::Language) {
    *app.tray_language.lock().unwrap() = language;
}

/// `refresh` also checks the current assignment with the control plane, off the main thread.
#[tauri::command]
async fn get_state(app: tauri::State<'_, Arc<App>>, refresh: bool) -> Result<View, AppMessage> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app.view(refresh))
        .await
        .map_err(|error| AppMessage::OperationFailed(error.to_string()))
}

#[tauri::command]
async fn login(app: tauri::State<'_, Arc<App>>, username: String, password: String,
               device: Option<String>) -> Result<View, AppMessage> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let api = Api::new(&app.sign_in_server).map_err(|_| AppMessage::InvalidServer)?;
        let device = device.filter(|d| !d.trim().is_empty()).unwrap_or_else(default_device_name);
        let username = username.trim();
        let resp = api.login(username, &password, device.trim(), platform())?;
        let mut session = Session::new(api.base().to_string(), resp.user, resp.device, resp.token);
        session.login_username = Some(username.to_owned());
        session.save(&app.paths)
            .map_err(|error| AppMessage::SessionSaveFailed(error.to_string()))?;
        app.set_message(None);
        Ok(app.view(true))
    })
    .await
    .map_err(|error| AppMessage::OperationFailed(error.to_string()))?
}

#[tauri::command]
async fn logout(app: tauri::State<'_, Arc<App>>) -> Result<View, AppMessage> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let outcome = commands::logout(&app.paths, &app.tunnel, &DesktopEffects)
            .map_err(|error| AppMessage::OperationFailed(error.to_string()))?;
        app.visitor.lock().unwrap().stop();
        match outcome {
            LoggedOut::SignedOut | LoggedOut::NotSignedIn => app.set_message(Some(AppMessage::SignedOut)),
            // A newer sign-in replaced the session while the server call was in flight: it stays signed in, and
            // its message stays as it is.
            LoggedOut::Superseded => {}
        }
        Ok(app.view(false))
    })
    .await
    .map_err(|error| AppMessage::OperationFailed(error.to_string()))?
}

#[tauri::command]
async fn connect(app: tauri::State<'_, Arc<App>>) -> Result<View, AppMessage> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        match commands::connect(&app.paths, &app.tunnel, &DesktopEffects)? {
            // A new Connect retries a visitor configuration that failed before.
            Connected::Started => app.visitor.lock().unwrap().reset(),
            // Signed out or replaced while the config synced: nothing was started for the old session. Return before
            // touching the app message or refreshing online, which would act for the replacement session.
            Connected::Superseded => return Err(AppMessage::SessionChangedWhileConnecting),
        }
        app.set_message(None);
        Ok(app.view(true))
    })
    .await
    .map_err(|error| AppMessage::OperationFailed(error.to_string()))?
}

#[tauri::command]
fn disconnect(app: tauri::State<Arc<App>>) -> Result<View, AppMessage> {
    app.request_stop().map_err(|error| AppMessage::OperationFailed(error.to_string()))?;
    app.set_message(None);
    Ok(app.view(false))
}

/// While connected: keep the heartbeat fresh, the config current and, on an XTCP exit, the visitor running.
fn background(app: Arc<App>) {
    let mut last_beat = Instant::now() - HEARTBEAT_EVERY;
    let mut last_sync = Instant::now();
    let launcher = launcher();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let status = app.tunnel.poll(&app.paths);
        {
            let mut visitor = app.visitor.lock().unwrap();
            // Re-read the requested connection under the visitor lock so Disconnect cannot leave a new guard behind.
            let status = status.as_ref().filter(|_| app.tunnel.wants_connection());
            if let Err(error) = visitor.ensure(&app.paths, &launcher, status) {
                eprintln!("Could not start the XTCP visitor: {error:#}");
            }
        }
        if !app.tunnel.wants_connection() {
            app.tunnel.release_if_stopped(&app.paths);
            continue;
        }
        if last_beat.elapsed() >= HEARTBEAT_EVERY {
            if let Err(error) = touch(&app.paths.heartbeat()) {
                let _ = app.request_stop();
                app.set_message(Some(AppMessage::OperationFailed(error.to_string())));
            }
            last_beat = Instant::now();
        }
        if last_sync.elapsed() >= SYNC_EVERY {
            last_sync = Instant::now();
            if let Some(s) = app.tunnel.session(&app.paths) {
                match sync_with_visitor(&app.paths, &s, DEFAULT_MODE) {
                    Ok(SyncOutcome::SignedOut) => {
                        let _ = app.request_stop();
                        app.set_message(Some(AppMessage::SessionExpiredDisconnected));
                    }
                    Ok(SyncOutcome::Unassigned(m)) => {
                        let _ = app.request_stop();
                        app.set_message(Some(AppMessage::EgressRevoked(m)));
                    }
                    Ok(SyncOutcome::XtcpUnavailable(m)) => {
                        let _ = app.request_stop();
                        app.set_message(Some(AppMessage::XtcpUnavailable(m)));
                    }
                    Ok(_) => {}
                    Err(_) => {} // offline for a moment: keep running on the current config
                }
            }
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("cli")) {
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(sidecar("aifree")).args(std::env::args_os().skip(2)).exec();
        eprintln!("Could not start the aifree CLI: {error}");
        std::process::exit(1);
    }
    let paths = Paths::new(None).expect("state directory");
    let sign_in_server = control_plane_url();
    let app = Arc::new(App {
        paths,
        sign_in_server,
        tunnel: Tunnel::default(),
        message: Mutex::new(None),
        assignment: Mutex::new(None),
        exit_observation: Mutex::new(None),
        tray_language: Mutex::new(tray::Language::preferred()),
        visitor: Mutex::new(VisitorProcess::default()),
    });
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| tray::show_window(app)));
    if updates::CONFIGURED {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }
    builder
        .manage(app)
        .manage(updates::PendingUpdate::default())
        .setup(|app| {
            let state = app.state::<Arc<App>>();
            // Only the primary instance gets here: the single-instance plugin ends a second launch while the app is
            // built, before setup. So this never touches the visitor of an instance that is already connected, and
            // kill_stale itself only removes an frpc whose guard is gone.
            visitor::kill_stale(&state.paths);
            let heartbeat = state.inner().clone();
            let exit = state.inner().clone();
            std::thread::spawn(move || background(heartbeat));
            std::thread::spawn(move || exit_probe::monitor(exit));
            updates::start_automatic_updates(app.handle().clone());
            if let Err(error) = tray::install(app.handle(), state.inner().clone()) {
                eprintln!("Could not create the system tray: {error}");
            }
            Ok(())
        })
        .on_window_event(tray::window_event)
        .invoke_handler(tauri::generate_handler![
            system_languages, set_tray_language, get_state, login, logout, connect, disconnect,
            netcheck::run_environment_check, updates::check_for_update, updates::install_update,
            updates::defer_update, updates::update_state,
        ])
        .build(tauri::generate_context!())
        .expect("building the app")
        .run(|handle, event| match event {
            tauri::RunEvent::Exit => {
                let app = handle.state::<Arc<App>>();
                if app.tunnel.owns_connection() {
                    let _ = app.request_stop();
                }
                app.visitor.lock().unwrap().stop();
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { has_visible_windows: false, .. } => tray::show_window(handle),
            _ => {}
        });
}
