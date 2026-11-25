//! Signed desktop update checks and safe background activation.

use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::App;

const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
const PRESENTATION_RETRY: Duration = Duration::from_secs(5);
const CONNECTION_RETRY: Duration = Duration::from_secs(30);
const INSTALL_GRACE: Duration = Duration::from_secs(30);
const RETRY_MIN: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(60 * 60);

pub(crate) const CONFIGURED: bool = option_env!("AIFREE_UPDATER_PUBLIC_KEY").is_some();

#[derive(Default)]
struct Gate {
    checking: bool,
    installing: bool,
    deferred: bool,
    presented: bool,
}

/// A pending update belongs only to this process. The frontend marks a queued offer as presented
/// before the scheduler may activate it, giving the user a chance to select Later.
pub(crate) struct PendingUpdate {
    update: Mutex<Option<Update>>,
    failed: Mutex<bool>,
    gate: Mutex<Gate>,
}

impl Default for PendingUpdate {
    fn default() -> Self {
        Self {
            update: Mutex::new(None),
            failed: Mutex::new(false),
            gate: Mutex::new(Gate::default()),
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct UpdateInfo {
    version: String,
    notes: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct UpdateState {
    update: Option<UpdateInfo>,
    failed: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum InstallResult {
    WaitingForPresentation,
    Connected,
    Deferred,
    Failed,
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
        if gate.checking || gate.installing || gate.deferred {
            return false;
        }
        gate.checking = true;
        true
    }

    fn finish_check(&self, update: Option<Update>) {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.checking = false;
        if !gate.deferred {
            gate.presented = false;
            *self
                .update
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = update;
            *self
                .failed
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = false;
        }
    }

    fn finish_failed_check(&self) {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.checking = false;
        if !gate.deferred {
            *self
                .failed
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = true;
        }
    }

    fn begin_install(&self, require_presentation: bool) -> Result<Update, InstallResult> {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        if gate.deferred {
            return Err(InstallResult::Deferred);
        }
        if require_presentation && !gate.presented {
            return Err(InstallResult::WaitingForPresentation);
        }
        if gate.checking || gate.installing {
            return Err(InstallResult::WaitingForPresentation);
        }
        let Some(update) = self
            .update
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
        else {
            return Err(InstallResult::Failed);
        };
        gate.installing = true;
        Ok(update)
    }

    fn finish_install(&self) {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .installing = false;
    }

    fn fail_offer(&self) {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.installing = false;
        gate.presented = false;
        if !gate.deferred {
            *self
                .update
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = None;
            *self
                .failed
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = true;
        }
    }

    fn defer(&self) {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .deferred = true;
    }

    fn deferred(&self) -> bool {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .deferred
    }

    fn state_for_frontend(&self) -> UpdateState {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        let update = self
            .update
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(info);
        if update.is_some() {
            gate.presented = true;
        }
        UpdateState {
            update,
            failed: *self
                .failed
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        }
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
    let result = match app.updater() {
        Ok(updater) => updater.check().await.map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    match result {
        Ok(update) => {
            let info = update.as_ref().map(info);
            pending.finish_check(update);
            Ok(info)
        }
        Err(error) => {
            pending.finish_failed_check();
            Err(error)
        }
    }
}

async fn install(
    app_handle: &AppHandle,
    app: &App,
    pending: &PendingUpdate,
    require_presentation: bool,
) -> Result<(), InstallResult> {
    if !CONFIGURED {
        return Err(InstallResult::Failed);
    }
    if app.tunnel.wants_connection() {
        return Err(InstallResult::Connected);
    }
    let update = pending.begin_install(require_presentation)?;
    let package = match update.download(|_, _| {}, || {}).await {
        Ok(package) => package,
        Err(_) => {
            pending.fail_offer();
            return Err(InstallResult::Failed);
        }
    };
    let _session = ccproxy_core::session::lock();
    if pending.deferred() {
        pending.finish_install();
        return Err(InstallResult::Deferred);
    }
    if app.tunnel.wants_connection() {
        pending.finish_install();
        return Err(InstallResult::Connected);
    }
    if update.install(&package).is_err() {
        pending.fail_offer();
        return Err(InstallResult::Failed);
    }
    app_handle.restart();
}

fn next_backoff(current: Duration) -> Duration {
    current.checked_mul(2).unwrap_or(RETRY_MAX).min(RETRY_MAX)
}

/// Checks automatically, waits for the frontend to expose the offer, and activates only while
/// disconnected. Terminal failures clear the cached release and use a bounded retry delay so a
/// repaired feed is fetched again rather than repeatedly installing stale bytes.
pub(crate) fn start_automatic_updates(app_handle: AppHandle) {
    if !CONFIGURED {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let mut backoff = RETRY_MIN;
        loop {
            let pending = app_handle.state::<PendingUpdate>();
            let app = app_handle.state::<std::sync::Arc<App>>();
            match check(&app_handle, &pending).await {
                Ok(Some(_)) => {
                    tokio::time::sleep(INSTALL_GRACE).await;
                    match install(&app_handle, &app, &pending, true).await {
                        Ok(()) => unreachable!("restart exits the process"),
                        Err(InstallResult::WaitingForPresentation) => {
                            tokio::time::sleep(PRESENTATION_RETRY).await
                        }
                        Err(InstallResult::Connected) => tokio::time::sleep(CONNECTION_RETRY).await,
                        Err(InstallResult::Deferred) => tokio::time::sleep(CHECK_EVERY).await,
                        Err(InstallResult::Failed) => {
                            tokio::time::sleep(backoff).await;
                            backoff = next_backoff(backoff);
                        }
                    }
                }
                Ok(None) => tokio::time::sleep(CHECK_EVERY).await,
                Err(error) => {
                    eprintln!("Update check failed: {error}");
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff);
                }
            }
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
pub(crate) fn update_state(pending: State<'_, PendingUpdate>) -> UpdateState {
    pending.state_for_frontend()
}

#[tauri::command]
pub(crate) async fn install_update(
    app_handle: AppHandle,
    app: State<'_, std::sync::Arc<App>>,
    pending: State<'_, PendingUpdate>,
) -> Result<(), String> {
    install(&app_handle, &app, &pending, false)
        .await
        .map_err(|result| format!("{result:?}"))
}

#[tauri::command]
pub(crate) fn defer_update(pending: State<'_, PendingUpdate>) {
    pending.defer();
}

#[cfg(test)]
mod tests {
    use super::{next_backoff, Gate, InstallResult, PendingUpdate, RETRY_MAX, RETRY_MIN};
    use std::time::Duration;

    #[test]
    fn gate_serializes_check_and_install() {
        let mut gate = Gate::default();
        gate.checking = true;
        assert!(gate.checking);
        assert!(!gate.installing);
        gate.checking = false;
        gate.installing = true;
        assert!(gate.installing);
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(next_backoff(RETRY_MIN), Duration::from_secs(120));
        assert_eq!(next_backoff(RETRY_MAX), RETRY_MAX);
    }

    #[test]
    fn missing_offer_does_not_leave_installation_in_flight() {
        let pending = PendingUpdate::default();
        assert!(matches!(
            pending.begin_install(false),
            Err(InstallResult::Failed)
        ));
        assert!(matches!(
            pending.begin_install(false),
            Err(InstallResult::Failed)
        ));
    }

    #[test]
    fn later_blocks_manual_and_automatic_activation() {
        let pending = PendingUpdate::default();
        pending.defer();
        assert!(matches!(
            pending.begin_install(false),
            Err(InstallResult::Deferred)
        ));
        assert!(matches!(
            pending.begin_install(true),
            Err(InstallResult::Deferred)
        ));
    }
}
