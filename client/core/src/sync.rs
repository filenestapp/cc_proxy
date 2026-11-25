//! Keep the local sing-box config in step with the control plane.

use crate::api::{Api, ConfigFetch};
use crate::session::{self, read_etag, write_atomic, Paths, Session};
use crate::visitor::{self, VisitorSync};
use anyhow::Result;
use std::fs;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncOutcome {
    /// A new config was written; a running supervisor picks it up on its own.
    Updated,
    Unchanged,
    /// The token is no longer valid; the session and config were removed and the tunnel must stop.
    SignedOut,
    /// No exit is assigned; the config was removed and the tunnel must stop. Carries the server's message.
    Unassigned(String),
    /// The session this poll was made for was signed out or replaced meanwhile; the reply was dropped.
    Superseded,
    /// The exit host uses XTCP, but this device cannot get a working visitor: carries the reason. The visitor files
    /// were removed (or never written); the tunnel must stop, since sing-box dials the visitor.
    XtcpUnavailable(String),
}

/// One poll. `mode` is the sing-box client mode to request (see [`crate::DEFAULT_MODE`]).
///
/// The request runs without any lock; its result is applied only if `session` is still the stored session, checked
/// and applied under [`session::lock`] (review finding CC-07).
pub fn sync_once(paths: &Paths, session: &Session, mode: &str) -> Result<SyncOutcome> {
    let api = Api::new(&session.server)?;
    // Only send the ETag if the file it describes is still there.
    let etag = if paths.config().exists() { read_etag(paths) } else { None };
    let reply = api.config(&session.token, mode, etag.as_deref())?;
    let _g = session::lock();
    if !Session::is_current(paths, &session.id) {
        return Ok(SyncOutcome::Superseded);
    }
    match reply {
        ConfigFetch::NotModified => Ok(SyncOutcome::Unchanged),
        ConfigFetch::Changed { etag, body } => {
            write_atomic(&paths.config(), &body, true)?;
            write_atomic(&paths.etag(), etag.as_bytes(), false)?;
            Ok(SyncOutcome::Updated)
        }
        ConfigFetch::Unauthorized => {
            Session::clear_locked(paths);
            Ok(SyncOutcome::SignedOut)
        }
        ConfigFetch::Unassigned(msg) => {
            let _ = fs::remove_file(paths.config());
            let _ = fs::remove_file(paths.etag());
            visitor::remove_config_files(paths);
            Ok(SyncOutcome::Unassigned(msg))
        }
    }
}

/// [`sync_once`] and then the XTCP visitor ([`visitor::sync_visitor`]): what the desktop app (and `ccproxy up
/// --visitor`) polls. Updated when either changed. A visitor whose settings do not match the tunnel config (sing-box
/// must dial the visitor's local port) is reported as [`SyncOutcome::XtcpUnavailable`].
pub fn sync_with_visitor(paths: &Paths, session: &Session, mode: &str) -> Result<SyncOutcome> {
    let config = sync_once(paths, session, mode)?;
    if !matches!(config, SyncOutcome::Updated | SyncOutcome::Unchanged) {
        return Ok(config);
    }
    let changed = match visitor::sync_visitor(paths, session)? {
        VisitorSync::SignedOut => return Ok(SyncOutcome::SignedOut),
        VisitorSync::Superseded => return Ok(SyncOutcome::Superseded),
        VisitorSync::Unavailable(msg) => return Ok(SyncOutcome::XtcpUnavailable(msg)),
        VisitorSync::Updated => true,
        VisitorSync::NotNeeded | VisitorSync::Unchanged => false,
    };
    if let Err(e) = visitor::check_entry(paths) {
        let _g = session::lock();
        visitor::remove_config_files(paths);
        return Ok(SyncOutcome::XtcpUnavailable(format!("{e:#}")));
    }
    Ok(if changed { SyncOutcome::Updated } else { config })
}
