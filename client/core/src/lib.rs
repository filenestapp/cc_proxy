//! Shared client logic for the aifree CLI and desktop app.
//!
//! * [`api`]: the control plane's client API (sign in, fetch config, sign out).
//! * [`session`]: where the signed-in session and the current sing-box config live on disk.
//! * [`sync`]: keep the local config in step with the control plane (ETag polling).
//! * [`supervisor`]: run sing-box, reload it when its config file changes, stop on request.
//! * [`commands`]: the desktop app's connect / disconnect / logout logic, applied only for the session that asked.
//! * [`elevate`]: start the supervisor with the privileges a TUN interface needs, per OS.
//! * [`sysdns`]: route rule domains' lookups to the TUN (macOS) and flush OS DNS caches.
//! * [`visitor`]: the unprivileged XTCP visitor (frpc) for exit hosts behind NAT, started after the TUN is up.
//!
//! The unprivileged side (GUI or CLI) only ever writes files: the config, a stop file and
//! a heartbeat. The privileged supervisor only reads them. No socket or IPC protocol sits between the two.

pub mod api;
pub mod commands;
pub mod elevate;
pub mod fsguard;
#[cfg(target_os = "linux")]
mod linux_stun;
pub mod runtime;
pub mod session;
pub mod supervisor;
pub mod sync;
pub mod sysdns;
pub mod visitor;

/// Mode the desktop client asks for: full TUN, DNS hijacked, domain rules from the control plane sent through
/// the tunnel, everything else direct. Works the same on macOS, Windows and Linux.
pub const DEFAULT_MODE: &str = "app";

pub fn control_plane_url() -> String {
    std::env::var("AIFREE_CONTROL_PLANE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| "https://cp.aifree.sg".to_owned())
}

pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Default device name: the computer's host name, trimmed to what the control plane accepts.
pub fn default_device_name() -> String {
    let raw = gethostname::gethostname().to_string_lossy().to_string();
    let cleaned: String = raw
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .take(64)
        .collect();
    if cleaned.is_empty() { "device".into() } else { cleaned }
}
