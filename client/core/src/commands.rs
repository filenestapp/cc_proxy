//! The desktop app's connect, disconnect and logout logic, with its network and privilege effects injected so tests
//! drive exactly what the app runs (review finding CC-07, issue #3).
//!
//! Both connect and logout wait on the network before their side effects. Meanwhile the user may sign out and sign
//! in again, possibly as someone else. A result is applied only if the session that started the command is still
//! the stored one, checked under [`session::lock`] together with the change that depends on it:
//!
//! * connect: after the config sync, the stop file, heartbeat, connection state and the elevated supervisor launch
//!   all happen under the lock, after checking the session. A superseded connect changes none of them.
//! * logout: the stop and the snapshot of the session to sign out are taken together under the lock, so a sign-in
//!   cannot land between them (stopping one session and revoking the next). The delayed server reply clears local
//!   state only for that session; a replacement session and its configuration are left alone.

use crate::session::{self, Paths, Session};
use crate::sync::SyncOutcome;
use anyhow::Result;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// What connect and logout need from the outside world. The desktop app implements it with the control plane API,
/// `sync_once` and the elevated launch; tests substitute their own.
pub trait Effects {
    /// Bring the local config in line with the control plane for `session` ([`crate::sync::sync_once`]).
    fn sync(&self, paths: &Paths, session: &Session) -> Result<SyncOutcome>;
    /// Start the privileged supervisor for the shared files in `paths`. May block on an OS password prompt.
    fn launch_supervisor(&self, paths: &Paths) -> Result<()>;
    /// Tell the control plane to revoke `session`'s device token.
    fn remote_logout(&self, session: &Session) -> Result<()>;
}

/// The app's wish to be connected and when it last connected, shared by the commands, the window and the
/// background heartbeat loop.
#[derive(Debug, Default)]
pub struct Tunnel {
    pub want_connected: AtomicBool,
    /// When the user last connected (seconds); supervisor status older than this belongs to an earlier run.
    pub connected_at: Mutex<u64>,
}

impl Tunnel {
    pub fn wants_connection(&self) -> bool {
        self.want_connected.load(Ordering::SeqCst)
    }

    pub fn connected_at(&self) -> u64 {
        *self.connected_at.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Disconnect: stop wanting the tunnel and tell the supervisor to stop.
    pub fn request_stop(&self, paths: &Paths) {
        self.want_connected.store(false, Ordering::SeqCst);
        touch(&paths.stop());
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Write the current time into a signal file (heartbeat, stop).
pub fn touch(path: &Path) {
    let _ = fs::write(path, now().to_string());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connected {
    /// The supervisor was launched for the session that asked.
    Started,
    /// That session was signed out or replaced while the config synced; nothing was changed.
    Superseded,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectError {
    SignInRequired,
    SessionExpired,
    Unassigned(String),
    Configuration(String),
    Authorization(String),
    /// The exit host uses XTCP and no working visitor can be set up for this device.
    Xtcp(String),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignInRequired => f.write_str("Sign in first."),
            Self::SessionExpired => f.write_str("Your session expired. Sign in again."),
            Self::Unassigned(detail) => write!(f, "No egress IP is assigned: {detail}"),
            Self::Configuration(detail) => write!(f, "Could not load the configuration: {detail}"),
            Self::Authorization(detail) => write!(f, "Administrator authorization was unavailable: {detail}"),
            Self::Xtcp(detail) => write!(f, "The XTCP visitor is unavailable: {detail}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Connect for the stored session, preserving the error reason separately from diagnostic text.
pub fn connect(paths: &Paths, tunnel: &Tunnel, fx: &dyn Effects) -> Result<Connected, ConnectError> {
    let session = Session::load(paths).ok_or(ConnectError::SignInRequired)?;
    match fx.sync(paths, &session).map_err(|error| ConnectError::Configuration(format!("{error:#}")))? {
        SyncOutcome::SignedOut => return Err(ConnectError::SessionExpired),
        SyncOutcome::Unassigned(detail) => return Err(ConnectError::Unassigned(detail)),
        SyncOutcome::XtcpUnavailable(detail) => return Err(ConnectError::Xtcp(detail)),
        SyncOutcome::Superseded => return Ok(Connected::Superseded),
        SyncOutcome::Updated | SyncOutcome::Unchanged => {}
    }
    // Held from the check through the launch: a sign-in or sign-out started meanwhile waits until the supervisor
    // is launched (or refused) for this session, so it cannot slip in between.
    let _g = session::lock();
    if !Session::is_current(paths, &session.id) {
        return Ok(Connected::Superseded);
    }
    let _ = fs::remove_file(paths.stop());
    *tunnel.connected_at.lock().unwrap_or_else(|e| e.into_inner()) = now();
    touch(&paths.heartbeat());
    tunnel.want_connected.store(true, Ordering::SeqCst);
    if let Err(error) = fx.launch_supervisor(paths) {
        tunnel.want_connected.store(false, Ordering::SeqCst);
        return Err(ConnectError::Authorization(format!("{error:#}")));
    }
    Ok(Connected::Started)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoggedOut {
    /// The session that asked was signed out locally (the server call is best effort, as before).
    SignedOut,
    /// No session was stored; leftover config files were removed.
    NotSignedIn,
    /// A newer sign-in replaced the session while the server call was in flight; it was left untouched.
    Superseded,
}

/// Sign out: stop the tunnel, revoke the token on the server, then forget the session that asked.
pub fn logout(paths: &Paths, tunnel: &Tunnel, fx: &dyn Effects) -> LoggedOut {
    let session = {
        let _g = session::lock();
        tunnel.request_stop(paths);
        match Session::load(paths) {
            Some(s) => s,
            None => {
                Session::clear_locked(paths);
                return LoggedOut::NotSignedIn;
            }
        }
    }; // released before the network call
    let _ = fx.remote_logout(&session);
    let _g = session::lock();
    if !Session::is_current(paths, &session.id) {
        return LoggedOut::Superseded;
    }
    Session::clear_locked(paths);
    LoggedOut::SignedOut
}
