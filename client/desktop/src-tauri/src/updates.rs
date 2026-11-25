//! Signed desktop update checks and installation.
//!
//! The updater plugin verifies every downloaded package against the public key bundled in
//! `tauri.conf.json`. The private signing key is only available to the release workflow.

use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::App;

pub(crate) const CONFIGURED: bool = option_env!("AIFREE_UPDATER_PUBLIC_KEY").is_some();

/// A pending update is process-local. A failed install discards it so the next attempt fetches
/// and verifies a new release manifest.
pub(crate) struct PendingUpdate(pub(crate) Mutex<Option<Update>>);

impl Default for PendingUpdate {
    fn default() -> Self {
        Self(Mutex::new(None))
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

async fn check(app: &AppHandle, pending: &PendingUpdate) -> Result<Option<UpdateInfo>, String> {
    if !CONFIGURED {
        return Ok(None);
    }
    let update = app
        .updater()
        .map_err(|error| error.to_string())?
        .check()
        .await
        .map_err(|error| error.to_string())?;
    let info = update.as_ref().map(info);
    *pending.0.lock().unwrap_or_else(|error| error.into_inner()) = update;
    Ok(info)
}

/// Check at launch so a verified update is ready when the window opens.
pub(crate) fn check_on_startup(app: AppHandle) {
    if !CONFIGURED {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let pending = app.state::<PendingUpdate>();
        if let Err(error) = check(&app, &pending).await {
            eprintln!("Update check failed: {error}");
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
    if !CONFIGURED {
        return Err("Desktop updates are not configured in this build.".into());
    }
    let update = pending
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
        .ok_or_else(|| "No update is ready. Check for updates again.".to_owned())?;
    // Downloading never changes the current installation or tunnel. The session lock shares the
    // same connection commit point as `commands::connect`, so a reconnect cannot race between the
    // final tunnel check and the platform installer activation.
    let package = update
        .download(|_, _| {}, || {})
        .await
        .map_err(|error| error.to_string())?;
    let _session = ccproxy_core::session::lock();
    if app.tunnel.wants_connection() {
        return Err("Disconnect before installing an update.".into());
    }
    update
        .install(&package)
        .map_err(|error| error.to_string())?;
    app_handle.restart();
}
