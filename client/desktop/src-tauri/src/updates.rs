//! Signed desktop update checks and safe background activation.

use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::App;

const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
const RETRY_WHEN_CONNECTED: Duration = Duration::from_secs(30);
const INSTALL_GRACE: Duration = Duration::from_secs(30);

pub(crate) const CONFIGURED: bool = option_env!("AIFREE_UPDATER_PUBLIC_KEY").is_some();

/// Serializes update work without holding a lock across a network request or installer call.
#[derive(Default)]
struct Gate {
    checking: bool,
    installing: bool,
    deferred: bool,
}

impl Gate {
    fn begin_check(&mut self) -> bool {
        if self.checking || self.installing || self.deferred {
            return false;
        }
        self.checking = true;
        true
    }

    fn finish_check(&mut self) {
        self.checking = false;
    }

    fn finish_install(&mut self) {
        self.installing = false;
    }

    fn defer(&mut self) {
        self.deferred = true;
    }
}

/// A pending update belongs only to this process. "Later" suppresses automatic installation until
/// the next launch, when the signed feed is checked again.
pub(crate) struct PendingUpdate {
    update: Mutex<Option<Update>>,
    gate: Mutex<Gate>,
}

impl Default for PendingUpdate {
    fn default() -> Self {
        Self {
            update: Mutex::new(None),
            gate: Mutex::new(Gate::default()),
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct UpdateInfo {
    version: String,
    notes: Option<String>,
}

fn info(update: &Update) -> UpdateInfo {
    UpdateInfo {
        version: update.version.clone(),
        notes: update.body.clone(),
    }
}

impl PendingUpdate {
    fn cached(&self) -> Option<UpdateInfo> {
        self.update
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(info)
    }

    fn begin_check(&self) -> bool {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.begin_check()
    }

    fn finish_check(&self, update: Option<Update>) {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.finish_check();
        if !gate.deferred {
            *self
                .update
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = update;
        }
    }

    fn begin_install(&self) -> Result<Update, String> {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        if gate.checking || gate.installing || gate.deferred {
            return Err(if gate.deferred {
                "The update was deferred until the next launch."
            } else {
                "An update is already being prepared."
            }
            .into());
        }
        let update = self
            .update
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .ok_or_else(|| "No update is ready. Check for updates again.".to_owned())?;
        gate.installing = true;
        Ok(update)
    }

    fn finish_install(&self) {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish_install();
    }

    fn defer(&self) {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .defer();
    }

    fn deferred(&self) -> bool {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .deferred
    }
}

async fn check(app: &AppHandle, pending: &PendingUpdate) -> Result<Option<UpdateInfo>, String> {
    if !CONFIGURED || pending.deferred() {
        return Ok(None);
    }
    if let Some(update) = pending.cached() {
        return Ok(Some(update));
    }
    if !pending.begin_check() {
        return Ok(pending.cached());
    }
    let result = app
        .updater()
        .map_err(|error| error.to_string())?
        .check()
        .await
        .map_err(|error| error.to_string());
    match result {
        Ok(update) => {
            let info = update.as_ref().map(info);
            pending.finish_check(update);
            Ok(info)
        }
        Err(error) => {
            pending.finish_check(None);
            Err(error)
        }
    }
}

async fn install(app_handle: &AppHandle, app: &App, pending: &PendingUpdate) -> Result<(), String> {
    if !CONFIGURED {
        return Err("Desktop updates are not configured in this build.".into());
    }
    if app.tunnel.wants_connection() {
        return Err("The proxy tunnel is still connected.".into());
    }
    let update = pending.begin_install()?;
    // Downloading does not change the installation or the running tunnel. The session lock shares
    // the same connection commit point as `commands::connect`, so a reconnect cannot slip between
    // this final check and activation of the platform installer.
    let package = match update.download(|_, _| {}, || {}).await {
        Ok(package) => package,
        Err(error) => {
            pending.finish_install();
            return Err(error.to_string());
        }
    };
    let _session = ccproxy_core::session::lock();
    if app.tunnel.wants_connection() || pending.deferred() {
        pending.finish_install();
        return Err("The update was deferred before installation.".into());
    }
    if let Err(error) = update.install(&package) {
        pending.finish_install();
        return Err(error.to_string());
    }
    app_handle.restart();
}

/// Check automatically, leave time for the user to choose Later, and install only while
/// disconnected. A connected tunnel causes a later safe-point retry instead of a restart.
pub(crate) fn start_automatic_updates(app_handle: AppHandle) {
    if !CONFIGURED {
        return;
    }
    tauri::async_runtime::spawn(async move {
        loop {
            let pending = app_handle.state::<PendingUpdate>();
            let app = app_handle.state::<std::sync::Arc<App>>();
            let found = check(&app_handle, &pending).await.ok().flatten().is_some();
            if found {
                tokio::time::sleep(INSTALL_GRACE).await;
                let _ = install(&app_handle, &app, &pending).await;
            }
            let delay = if pending.cached().is_some() && !pending.deferred() {
                RETRY_WHEN_CONNECTED
            } else {
                CHECK_EVERY
            };
            tokio::time::sleep(delay).await;
        }
    });
}

#[tauri::command]
pub(crate) async fn check_for_update(
    app: AppHandle,
    pending: State<'_, PendingUpdate>,
) -> Result<Option<UpdateInfo>, String> {
    check(&app, &pending).await
}

#[tauri::command]
pub(crate) async fn install_update(
    app_handle: AppHandle,
    app: State<'_, std::sync::Arc<App>>,
    pending: State<'_, PendingUpdate>,
) -> Result<(), String> {
    install(&app_handle, &app, &pending).await
}

#[tauri::command]
pub(crate) fn defer_update(pending: State<'_, PendingUpdate>) {
    pending.defer();
}

#[cfg(test)]
mod tests {
    use super::Gate;

    #[test]
    fn gate_serializes_check_and_install() {
        let mut gate = Gate::default();
        assert!(gate.begin_check());
        assert!(!gate.begin_check());
        assert!(!gate.installing);
        gate.finish_check();
        gate.installing = true;
        assert!(gate.installing);
        assert!(!gate.begin_check());
        gate.finish_install();
        assert!(!gate.installing);
        assert!(gate.begin_check());
    }

    #[test]
    fn deferred_gate_blocks_future_automatic_work() {
        let mut gate = Gate::default();
        gate.defer();
        assert!(gate.deferred);
        assert!(!gate.begin_check());
        assert!(!gate.installing);
    }
}
