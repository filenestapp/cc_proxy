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
    // Refresh an unreadable or missing config, including a copy left by the legacy privileged client.
    let readable_config = crate::fsguard::open_no_follow(&paths.config())
        .is_ok_and(|file| file.metadata().is_ok_and(|metadata| metadata.is_file()));
    let etag = if readable_config { read_etag(paths) } else { None };
    let reply = api.config(&session.token, mode, etag.as_deref())?;
    let _g = session::lock(paths)?;
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

/// Poll the tunnel config and XTCP visitor for the CLI and desktop app. The visitor and its tunnel entry must agree.
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
        // An older control plane without the endpoint: connect exactly as before this feature.
        VisitorSync::NotNeeded | VisitorSync::Unchanged | VisitorSync::Unsupported => false,
    };
    let _g = session::lock(paths)?;
    if !Session::is_current(paths, &session.id) {
        return Ok(SyncOutcome::Superseded);
    }
    if let Err(e) = visitor::check_entry(paths) {
        visitor::remove_config_files(paths);
        return Ok(SyncOutcome::XtcpUnavailable(format!("{e:#}")));
    }
    Ok(if changed { SyncOutcome::Updated } else { config })
}
