//! Connection and sign-out coordination shared by the CLI and the desktop app.
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
use crate::supervisor::Status;
use crate::sync::SyncOutcome;
use anyhow::{Context, Result};
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const HEARTBEAT_TIMEOUT_SECS: u64 = 60;
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

/// What connect and logout need from the outside world. The desktop app implements it with the control plane API,
/// `sync_once` and the elevated launch; tests substitute their own.
pub trait Effects {
    /// Bring the local config in line with the control plane for `session` ([`crate::sync::sync_once`]).
    fn sync(&self, paths: &Paths, session: &Session) -> Result<SyncOutcome>;
    /// Start the privileged supervisor for the shared files in `paths`. May block on an OS password prompt.
    fn launch_supervisor(&self, paths: &Paths, connection_id: &str) -> Result<()>;
    /// Tell the control plane to revoke `session`'s device token.
    fn remote_logout(&self, session: &Session) -> Result<()>;
}

/// The local connection owner. A GUI and CLI for the same state directory share an OS file lock.
#[derive(Debug, Default)]
pub struct Tunnel {
    want_connected: AtomicBool,
    owner: Mutex<Option<Connection>>,
}

#[derive(Debug)]
struct Connection {
    _lock: fs::File,
    session_id: String,
    started: Instant,
}

impl Tunnel {
    pub fn wants_connection(&self) -> bool {
        self.want_connected.load(Ordering::SeqCst)
    }

    pub fn owns_connection(&self) -> bool {
        self.owner.lock().unwrap().is_some()
    }

    /// Either frontend can stop the connection. Its owner keeps the lock until the supervisor finishes cleanup.
    pub fn request_stop(&self, paths: &Paths) -> Result<()> {
        let _g = session::lock(paths)?;
        self.stop_locked(paths)
    }

    fn stop_locked(&self, paths: &Paths) -> Result<()> {
        stop_locked(paths)?;
        self.want_connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Detect a stop from the other frontend, a replacement session, or a supervisor that has exited.
    pub fn poll(&self, paths: &Paths) -> Option<Status> {
        let owner = self.owner.lock().unwrap();
        let connection = owner.as_ref()?;
        let status = Status::for_paths(paths);
        let terminal = status.as_ref().is_some_and(|status| !status.is_active());
        let timed_out = status.is_none() && connection.started.elapsed() >= STARTUP_TIMEOUT;
        if timed_out || !Session::is_current(paths, &connection.session_id) {
            // The connection lock still belongs to this run, so this cannot stop a replacement run.
            let _ = self.stop_locked(paths);
        }
        let stopping = paths.stop().exists();
        if stopping || terminal {
            self.want_connected.store(false, Ordering::SeqCst);
        }
        status
    }

    /// Call after the owner's visitor has exited and the privileged tunnel has finished stopping.
    pub fn release_if_stopped(&self, paths: &Paths) {
        let mut owner = self.owner.lock().unwrap();
        if !self.wants_connection() && !Status::for_paths(paths).is_some_and(|status| status.is_active()) {
            *owner = None;
        }
    }

    pub fn session(&self, paths: &Paths) -> Option<Session> {
        let owner = self.owner.lock().unwrap();
        let session = Session::load(paths)?;
        (session.id == owner.as_ref()?.session_id).then_some(session)
    }
}

pub fn try_connection_lock(paths: &Paths) -> Result<Option<fs::File>> {
    session::try_lock(&paths.dir.join("connection.lock"))
}

/// Read the requested connection even when it was started by a different frontend.
pub fn connection_requested(paths: &Paths, status: Option<&Status>) -> bool {
    if paths.stop().exists() {
        return false;
    }
    match status {
        Some(status) => status.is_active(),
        None => paths.connection_id().exists() && matches!(try_connection_lock(paths), Ok(None)),
    }
}

pub(crate) fn stop_locked(paths: &Paths) -> Result<()> {
    fs::write(paths.stop(), session::new_session_id()).context("writing the tunnel stop request")
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
    Busy,
    Canceled,
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
            Self::Busy => f.write_str("A connection is already active or stopping. Use status or disconnect."),
            Self::Canceled => f.write_str("The connection was canceled."),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Connect for the stored session, preserving the error reason separately from diagnostic text.
pub fn connect(paths: &Paths, tunnel: &Tunnel, fx: &dyn Effects) -> Result<Connected, ConnectError> {
    fn state_error(error: anyhow::Error) -> ConnectError {
        ConnectError::Configuration(format!("{error:#}"))
    }

    let lock = try_connection_lock(paths).map_err(state_error)?.ok_or(ConnectError::Busy)?;
    if Status::for_paths(paths).is_some_and(|status| status.is_active()) {
        return Err(ConnectError::Busy);
    }
    let session = Session::load(paths).ok_or(ConnectError::SignInRequired)?;
    let previous_stop = session::read_file_trimmed(&paths.stop());
    match fx.sync(paths, &session).map_err(|error| ConnectError::Configuration(format!("{error:#}")))? {
        SyncOutcome::SignedOut => return Err(ConnectError::SessionExpired),
        SyncOutcome::Unassigned(detail) => return Err(ConnectError::Unassigned(detail)),
        SyncOutcome::XtcpUnavailable(detail) => return Err(ConnectError::Xtcp(detail)),
        SyncOutcome::Superseded => return Ok(Connected::Superseded),
        SyncOutcome::Updated | SyncOutcome::Unchanged => {}
    }
    // Held from the check through the launch: a sign-in or sign-out started meanwhile waits until the supervisor
    // is launched (or refused) for this session, so it cannot slip in between.
    let _g = session::lock(paths).map_err(state_error)?;
    if !Session::is_current(paths, &session.id) {
        return Ok(Connected::Superseded);
    }
    if session::read_file_trimmed(&paths.stop()) != previous_stop {
        return Err(ConnectError::Canceled);
    }
    let connection_id = session::new_session_id();
    session::write_atomic(&paths.connection_id(), connection_id.as_bytes(), false).map_err(state_error)?;
    match fs::remove_file(paths.stop()) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(state_error(error.into())),
    }
    touch(&paths.heartbeat());
    *tunnel.owner.lock().unwrap() = Some(Connection { _lock: lock, session_id: session.id, started: Instant::now() });
    tunnel.want_connected.store(true, Ordering::SeqCst);
    if let Err(error) = fx.launch_supervisor(paths, &connection_id) {
        let _ = tunnel.stop_locked(paths);
        *tunnel.owner.lock().unwrap() = None;
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
pub fn logout(paths: &Paths, tunnel: &Tunnel, fx: &dyn Effects) -> Result<LoggedOut> {
    let session = {
        let _g = session::lock(paths)?;
        tunnel.stop_locked(paths)?;
        match Session::load(paths) {
            Some(s) => s,
            None => {
                Session::clear_locked(paths);
                return Ok(LoggedOut::NotSignedIn);
            }
        }
    }; // released before the network call
    let _ = fx.remote_logout(&session);
    let _g = session::lock(paths)?;
    if !Session::is_current(paths, &session.id) {
        return Ok(LoggedOut::Superseded);
    }
    Session::clear_locked(paths);
    Ok(LoggedOut::SignedOut)
}
