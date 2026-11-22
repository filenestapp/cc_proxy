//! On-disk state: the signed-in session and the files shared with the privileged supervisor.
//!
//! Layout of the state directory (default: the OS config dir + `cc-proxy`):
//!   session.json      server, user, device, token (mode 0600 on Unix)
//!   sing-box.json     current sing-box config (0600), written by the unprivileged side
//!   config.etag       ETag of sing-box.json
//!   stop              presence tells the supervisor to stop
//!   heartbeat         touched by the GUI; the supervisor stops when it goes stale
//!
//! The privileged supervisor only reads sing-box.json (through `runtime::accept`) and stats stop / heartbeat. Its
//! own files (validated config, working dir, log, status) live in `runtime::protected_dir()`, not here.
//! The token is a revocable device credential, not the password; the password is never stored.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub server: String,
    pub user: String,
    pub device: String,
    pub token: String,
    /// Changes with every sign-in. A network result is applied only if it belongs to the current session
    /// (review finding CC-07): a slow reply for a session that was signed out and replaced must not touch the new one.
    #[serde(default)]
    pub id: String,
}

static SESSION_LOCK: Mutex<()> = Mutex::new(());

/// Serialises sign-in, sign-out and the commit of network results within this process. Hold it across "is this
/// still the current session?" and the change that depends on the answer.
pub fn lock() -> MutexGuard<'static, ()> {
    SESSION_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A fresh session id (not a secret; it only has to differ between sign-ins).
pub fn new_session_id() -> String {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    h.write_u32(std::process::id());
    format!("{:016x}{:016x}", h.finish(), RandomState::new().build_hasher().finish())
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn new(dir: Option<PathBuf>) -> Result<Self> {
        let dir = match dir {
            Some(d) => d,
            None => dirs::config_dir().context("no config directory on this system")?.join("cc-proxy"),
        };
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Paths { dir })
    }
    pub fn session(&self) -> PathBuf { self.dir.join("session.json") }
    pub fn config(&self) -> PathBuf { self.dir.join("sing-box.json") }
    pub fn etag(&self) -> PathBuf { self.dir.join("config.etag") }
    pub fn stop(&self) -> PathBuf { self.dir.join("stop") }
    pub fn heartbeat(&self) -> PathBuf { self.dir.join("heartbeat") }
}

/// Write via a temp file + rename, so readers never see half a file. `private` sets 0600 on Unix.
pub fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        let _ = private;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

impl Session {
    pub fn load(paths: &Paths) -> Option<Session> {
        let data = fs::read(paths.session()).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// A new session from a sign-in; gets its own id.
    pub fn new(server: String, user: String, device: String, token: String) -> Session {
        Session { server, user, device, token, id: new_session_id() }
    }

    /// Replace the stored session (sign-in). The config of any previous session goes with it.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let _g = lock();
        for p in [paths.config(), paths.etag()] {
            let _ = fs::remove_file(p);
        }
        write_atomic(&paths.session(), &serde_json::to_vec_pretty(self)?, true)
    }

    /// Forget the session and the config derived from it.
    pub fn clear(paths: &Paths) {
        let _g = lock();
        Session::clear_locked(paths);
    }

    /// [`Session::clear`] for callers already holding [`lock`].
    pub fn clear_locked(paths: &Paths) {
        for p in [paths.session(), paths.config(), paths.etag()] {
            let _ = fs::remove_file(p);
        }
    }

    /// Whether `id` is still the stored session. Call with [`lock`] held when acting on the answer.
    pub fn is_current(paths: &Paths, id: &str) -> bool {
        Session::load(paths).map(|s| s.id == id).unwrap_or(false)
    }
}

pub fn read_etag(paths: &Paths) -> Option<String> {
    fs::read_to_string(paths.etag()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
