//! Signed desktop update checks and safe background activation.

use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::sync::Notify;

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
    presented_at: Option<Instant>,
    activation_claimed: bool,
}

impl Gate {
    fn can_check(&self) -> bool {
        !self.checking && !self.installing && !self.deferred && !self.activation_claimed
    }

    fn mark_presented(&mut self, now: Instant) {
        self.presented_at.get_or_insert(now);
    }

    fn activation_delay(&self, now: Instant) -> Option<Duration> {
        if self.deferred || self.activation_claimed {
            return None;
        }
        self.presented_at
            .map(|time| INSTALL_GRACE.saturating_sub(now.saturating_duration_since(time)))
    }
}

/// A pending update belongs only to this process. The frontend marks a queued offer as presented
/// before the scheduler may activate it, giving the user a chance to select Later.
pub(crate) struct PendingUpdate {
    update: Mutex<Option<Update>>,
    failed: Mutex<bool>,
    gate: Mutex<Gate>,
    check_requested: Notify,
}

impl Default for PendingUpdate {
    fn default() -> Self {
        Self {
            update: Mutex::new(None),
            failed: Mutex::new(false),
            gate: Mutex::new(Gate::default()),
            check_requested: Notify::new(),
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

enum CheckResult {
    Offer(Option<UpdateInfo>),
    Busy,
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
        if !gate.can_check() {
            return false;
        }
        gate.checking = true;
        true
    }

    pub(crate) fn request_check(&self) {
        let gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        if gate.can_check() && self.cached().is_none() {
            self.check_requested.notify_one();
        }
    }

    async fn wait_for_check(&self, delay: Duration) {
        let _ = tokio::time::timeout(delay, self.check_requested.notified()).await;
    }

    fn finish_check(&self, update: Option<Update>) {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.checking = false;
        if !gate.deferred {
            gate.presented_at = None;
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
        if require_presentation && gate.presented_at.is_none() {
            return Err(InstallResult::WaitingForPresentation);
        }
        if gate.checking || gate.installing || gate.activation_claimed {
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
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.installing = false;
        gate.activation_claimed = false;
    }

    fn fail_offer(&self) {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        gate.installing = false;
        gate.activation_claimed = false;
        gate.presented_at = None;
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

    fn defer(&self) -> bool {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        if gate.activation_claimed {
            return false;
        }
        gate.deferred = true;
        true
    }

    fn deferred(&self) -> bool {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .deferred
    }

    fn checking(&self) -> bool {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .checking
    }

    fn activation_delay(&self) -> Option<Duration> {
        self.gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .activation_delay(Instant::now())
    }

    fn claim_activation(&self) -> bool {
        let mut gate = self.gate.lock().unwrap_or_else(|error| error.into_inner());
        if gate.deferred || gate.activation_claimed {
            return false;
        }
        gate.activation_claimed = true;
        true
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
            gate.mark_presented(Instant::now());
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

async fn check(app: &AppHandle, pending: &PendingUpdate) -> Result<CheckResult, String> {
    if !CONFIGURED || pending.deferred() {
        return Ok(CheckResult::Offer(None));
    }
    if let Some(update) = pending.cached() {
        return Ok(CheckResult::Offer(Some(update)));
    }
    if !pending.begin_check() {
        return if pending.checking() {
            Ok(CheckResult::Busy)
        } else {
            Ok(CheckResult::Offer(pending.cached()))
        };
    }
    let result = match app.updater() {
        Ok(updater) => updater.check().await.map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    match result {
        Ok(update) => {
            let info = update.as_ref().map(info);
            pending.finish_check(update);
            Ok(CheckResult::Offer(info))
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
    if app.tunnel.owns_connection() || app.current_status().is_some_and(|status| status.is_active()) {
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
    let Ok(Some(_connection)) = ccproxy_core::commands::try_connection_lock(&app.paths) else {
        pending.finish_install();
        return Err(InstallResult::Connected);
    };
    let Ok(_session) = ccproxy_core::session::lock(&app.paths) else {
        pending.finish_install();
        return Err(InstallResult::Failed);
    };
    if app.current_status().is_some_and(|status| status.is_active()) {
        pending.finish_install();
        return Err(InstallResult::Connected);
    }
    if !pending.claim_activation() {
        pending.finish_install();
        return Err(InstallResult::Deferred);
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
                Ok(CheckResult::Offer(Some(_))) => {
                    let Some(delay) = pending.activation_delay() else {
                        tokio::time::sleep(PRESENTATION_RETRY).await;
                        continue;
                    };
                    tokio::time::sleep(delay).await;
                    match install(&app_handle, &app, &pending, true).await {
                        Ok(()) => unreachable!("restart exits the process"),
                        Err(InstallResult::WaitingForPresentation) => {
                            tokio::time::sleep(PRESENTATION_RETRY).await
                        }
                        Err(InstallResult::Connected) => tokio::time::sleep(CONNECTION_RETRY).await,
                        Err(InstallResult::Deferred) => tokio::time::sleep(CHECK_EVERY).await,
                        Err(InstallResult::Failed) => {
                            pending.wait_for_check(backoff).await;
                            backoff = next_backoff(backoff);
                        }
                    }
                }
                Ok(CheckResult::Offer(None)) => pending.wait_for_check(CHECK_EVERY).await,
                Ok(CheckResult::Busy) => tokio::time::sleep(PRESENTATION_RETRY).await,
                Err(error) => {
                    eprintln!("Update check failed: {error}");
                    pending.wait_for_check(backoff).await;
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
    match check(&app, &pending).await? {
        CheckResult::Offer(update) => Ok(update),
        CheckResult::Busy => Ok(None),
    }
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
pub(crate) fn defer_update(pending: State<'_, PendingUpdate>) -> Result<(), String> {
    pending
        .defer()
        .then_some(())
        .ok_or_else(|| "The update is already being activated.".into())
}

#[cfg(test)]
mod tests {
    use super::{
        next_backoff, Gate, InstallResult, PendingUpdate, CHECK_EVERY, INSTALL_GRACE,
        PRESENTATION_RETRY, RETRY_MAX, RETRY_MIN,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn gate_serializes_check_and_install() {
        let pending = PendingUpdate::default();
        assert!(pending.begin_check());
        assert!(!pending.begin_check());
        assert!(matches!(
            pending.begin_install(false),
            Err(InstallResult::WaitingForPresentation)
        ));
        pending.finish_check(None);
        assert!(pending.begin_check());
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(next_backoff(RETRY_MIN), Duration::from_secs(120));
        assert_eq!(next_backoff(RETRY_MAX), RETRY_MAX);
    }

    #[test]
    fn reopening_wakes_the_scheduler_before_its_timer_expires() {
        let pending = PendingUpdate::default();
        tauri::async_runtime::block_on(async {
            let mut waiting = Box::pin(pending.wait_for_check(CHECK_EVERY));
            assert!(tokio::time::timeout(Duration::ZERO, &mut waiting)
                .await
                .is_err());
            pending.request_check();
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .expect("the reopen request should wake the update check");
        });
    }

    #[test]
    fn reopen_requests_coalesce_and_respect_the_gate() {
        let pending = PendingUpdate::default();
        tauri::async_runtime::block_on(async {
            pending.request_check();
            pending.request_check();
            tokio::time::timeout(Duration::from_secs(1), pending.wait_for_check(CHECK_EVERY))
                .await
                .expect("an early reopen request should be retained");

            assert!(pending.begin_check());
            pending.request_check();
            pending.finish_check(None);
            assert!(
                tokio::time::timeout(Duration::ZERO, pending.wait_for_check(CHECK_EVERY))
                    .await
                    .is_err()
            );

            assert!(pending.defer());
            pending.request_check();
            assert!(
                tokio::time::timeout(Duration::ZERO, pending.wait_for_check(CHECK_EVERY))
                    .await
                    .is_err()
            );
        });
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
        assert!(pending.defer());
        assert!(matches!(
            pending.begin_install(false),
            Err(InstallResult::Deferred)
        ));
        assert!(matches!(
            pending.begin_install(true),
            Err(InstallResult::Deferred)
        ));
    }

    #[test]
    fn busy_check_keeps_the_scheduler_in_the_short_retry_window() {
        let pending = PendingUpdate::default();
        assert!(pending.begin_check());
        assert!(pending.checking());
        assert_eq!(PRESENTATION_RETRY, Duration::from_secs(5));
        pending.finish_failed_check();
        assert!(!pending.checking());
    }

    #[test]
    fn activation_claim_rejects_a_late_deferral() {
        let pending = PendingUpdate::default();
        assert!(pending.claim_activation());
        assert!(!pending.defer());
    }

    #[test]
    fn presentation_grace_waits_for_the_frontend_and_is_not_reset_by_polling() {
        let mut gate = Gate::default();
        let started = Instant::now();
        let presented = started + INSTALL_GRACE + Duration::from_secs(10);

        assert_eq!(gate.activation_delay(started), None);
        assert_eq!(gate.activation_delay(presented), None);

        gate.mark_presented(presented);
        assert_eq!(gate.activation_delay(presented), Some(INSTALL_GRACE));

        let next_poll = presented + Duration::from_secs(5);
        gate.mark_presented(next_poll);
        assert_eq!(
            gate.activation_delay(next_poll),
            Some(INSTALL_GRACE - Duration::from_secs(5))
        );
        assert_eq!(
            gate.activation_delay(presented + INSTALL_GRACE),
            Some(Duration::ZERO)
        );
    }
}
