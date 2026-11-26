//! Run sing-box and keep it matched to its config file. This is the only part that needs privileges (TUN).
//!
//! The supervisor reads files written by the unprivileged side and never talks to the network itself:
//!
//! * config file changes: `sing-box check`, then reload (SIGHUP on Unix, restart on Windows); a config that
//!   fails the check is ignored and the running one stays
//! * config file removed: stop (signed out, or no exit assigned)
//! * stop file appears: stop
//! * heartbeat goes stale: stop (the app that started us is gone)
//! * sing-box exits: restart, at most MAX_RESTARTS per minute
//!
//! After start and every reload the OS resolver is pointed at the TUN for the rule domains and its cache is
//! flushed ([`sysdns`]); on every way out both are undone.
//!
//! Progress goes to a status file in the protected runtime directory, readable by the app. See [`runtime`] for the
//! privilege boundary: the client's config is validated and re-rendered before sing-box ever sees it.

use crate::runtime::{self, write_protected};
use crate::session::{self, Paths};
use crate::{sysdns, visitor};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_RESTARTS: usize = 5;

#[derive(Debug, Clone)]
pub struct Options {
    pub singbox: PathBuf,
    /// The exact path of the frpc sidecar shipped alongside this supervisor.
    pub bundled_frpc: Option<PathBuf>,
    /// The client's config, in the user-writable state directory. Only read, through [`runtime::accept`].
    pub client_config: PathBuf,
    /// User-writable signals; only their existence / modification time is looked at.
    pub stop_file: PathBuf,
    /// Heartbeat file and how old it may get before we stop. None for the legacy privileged `up` command.
    pub heartbeat: Option<(PathBuf, Duration)>,
    /// A delayed supervisor must still belong to the connection that requested it.
    pub connection_id: Option<String>,
    pub poll: Duration,
    /// Where the supervisor keeps its own files: [`runtime::protected_dir`] in production.
    pub runtime_dir: PathBuf,
    /// Refuse a runtime dir that is not root / Administrators-owned. False only in unit tests.
    pub require_privileged: bool,
}

impl Options {
    fn config(&self) -> PathBuf { self.runtime_dir.join("config.json") }
    fn candidate(&self) -> PathBuf { self.runtime_dir.join("candidate.json") }
    fn workdir(&self) -> PathBuf { self.runtime_dir.join("work") }
    fn cache(&self) -> PathBuf { self.runtime_dir.join("work").join("cache.db") }
    fn log(&self) -> PathBuf { self.runtime_dir.join("tunnel.log") }
    fn status(&self) -> PathBuf { self.runtime_dir.join("status.json") }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Status {
    /// starting | running | stopped | failed
    pub state: String,
    pub pid: Option<u32>,
    pub message: String,
    pub updated: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_pid: Option<u32>,
    /// Advances only when the TUN starts or its routes are reloaded.
    #[serde(default)]
    pub route_generation: u64,
    /// Identifies the loaded exit without exposing its connection credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_fingerprint: Option<String>,
}

impl Status {
    pub fn is_active(&self) -> bool {
        matches!(self.state.as_str(), "starting" | "running")
    }

    /// A visitor must establish its UDP path after this specific TUN route generation is ready.
    pub fn running_route(&self) -> Option<(u32, u64)> {
        if self.state != "running" {
            return None;
        }
        Some((self.pid?, self.route_generation))
    }

    pub fn read(path: &Path) -> Option<Status> {
        serde_json::from_slice(&fs::read(path).ok()?).ok()
    }

    /// The tunnel status the supervisor publishes (readable without privileges).
    pub fn current() -> Option<Status> {
        Status::read(&runtime::status_path())
    }

    pub fn for_paths(paths: &Paths) -> Option<Status> {
        let connection_id = session::read_file_trimmed(&paths.connection_id());
        let mut status = Self::current().filter(|status| status.connection_id == connection_id)?;
        if status.is_active() && status.supervisor_pid.is_some_and(|pid| !process_exists(pid)) {
            status.state = "failed".into();
            status.pid = None;
            status.message = "The tunnel supervisor exited unexpectedly.".into();
        }
        Some(status)
    }
}

pub(crate) fn process_exists(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
        let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if process.is_null() {
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let dead = WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
        CloseHandle(process);
        !dead
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    interrupt();
}

#[cfg(windows)]
unsafe extern "system" fn on_console_signal(kind: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if matches!(kind, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        interrupt();
        return 1;
    }
    0
}

/// Whether Ctrl-C / SIGTERM arrived since [`install_signal_handlers`].
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Request shutdown for a supervisor running in this process.
pub fn interrupt() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Stop cleanly on Ctrl-C, Ctrl-Break on Windows, or SIGTERM on Unix.
pub fn install_signal_handlers() {
    #[cfg(unix)]
    unsafe {
        let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_console_signal), 1);
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Modification time without following links (the user directory is not trusted).
fn mtime(path: &Path) -> Option<SystemTime> {
    fs::symlink_metadata(path).and_then(|m| m.modified()).ok()
}

struct Supervisor {
    o: Options,
    child: Option<Child>,
    restarts: Vec<Instant>,
    route_generation: u64,
    /// The protected config sing-box is running (the accepted rendering).
    running: Option<Value>,
}

impl Supervisor {
    fn status(&self, state: &str, message: &str) {
        let egress_fingerprint = self.running.as_ref()
            .filter(|_| state == "running")
            .and_then(|config| config.pointer("/outbounds/0"))
            .map(runtime::egress_fingerprint);
        let s = Status {
            state: state.into(),
            pid: self.child.as_ref().map(|c| c.id()),
            message: message.into(),
            updated: now(),
            connection_id: self.o.connection_id.clone(),
            supervisor_pid: Some(std::process::id()),
            route_generation: self.route_generation,
            egress_fingerprint,
        };
        if self.guard().is_err() {
            return;
        }
        if let Ok(data) = serde_json::to_vec_pretty(&s) {
            let _ = write_protected(&self.o.status(), &data, false);
        }
    }

    fn publish_ready_routes(&mut self, message: &str) -> Result<()> {
        // Let sing-box bring the TUN up before pointing the resolver at it.
        std::thread::sleep(Duration::from_millis(1500));
        if self.stop_reason().is_some() {
            return Ok(());
        }
        let child = self.child.as_mut().context("missing sing-box process")?;
        if child.try_wait()?.is_none() {
            sysdns::apply(&self.o.config());
            if child.try_wait()?.is_none() {
                self.route_generation += 1;
                self.status("running", message);
            }
        }
        Ok(())
    }

    /// Re-verify the runtime directory before writing into it with privileges.
    fn guard(&self) -> Result<()> {
        runtime::verify_protected_dir(&self.o.runtime_dir, self.o.require_privileged)
    }

    fn singbox_check(&self, config: &Path) -> Result<()> {
        let out = Command::new(&self.o.singbox)
            .args(["check", "-c"])
            .arg(config)
            .output()
            .with_context(|| format!("running {}", self.o.singbox.display()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(anyhow!("sing-box check: {}", String::from_utf8_lossy(&out.stderr).trim()))
        }
    }

    /// Take the client's current config through the privilege boundary. Ok(true): the protected config changed
    /// (and passed `sing-box check`); Ok(false): it is what is already running.
    fn load(&mut self) -> Result<bool> {
        let raw = runtime::read_client_config(&self.o.client_config)?;
        let (spec, mut protected) = runtime::accept(&raw, &self.o.cache())?;
        if spec.stun.is_some() && spec.server == visitor::BIND_ADDR {
            if let Some(frpc) = self.o.bundled_frpc.as_deref().and_then(Path::to_str) {
                // The XTCP visitor uses IPv4 STUN before it can carry traffic. The
                // supervisor grants that exception by exact path in its protected copy.
                protected["route"]["rules"].as_array_mut().expect("rendered route rules").insert(
                    runtime::STUN_RULE_INDEX,
                    serde_json::json!({
                        "ip_version": 4, "network": "udp", "protocol": "stun", "process_path": [frpc], "outbound": "direct",
                    }),
                );
            }
        }
        if self.running.as_ref() == Some(&protected) {
            return Ok(false);
        }
        let bytes = serde_json::to_vec_pretty(&protected)?;
        self.guard()?;
        write_protected(&self.o.candidate(), &bytes, true)?;
        self.singbox_check(&self.o.candidate())?;
        fs::rename(self.o.candidate(), self.o.config())?;
        self.running = Some(protected);
        Ok(true)
    }

    fn start(&mut self) -> Result<()> {
        self.guard()?;
        // Entries a previous version may have left: the work directory gets the same check as the runtime directory
        // (moved aside if it fails), and the cache and log are removed unless they are plain files only the
        // supervisor's accounts can write. sing-box opens the cache itself, following links.
        let privileged = self.o.require_privileged;
        runtime::prepare_protected_dir(&self.o.workdir(), privileged)?;
        runtime::clean_protected_file(&self.o.cache(), privileged)?;
        let log = runtime::open_protected_log(&self.o.log(), privileged)?;
        let mut command = Command::new(&self.o.singbox);
        command.args(["run", "-c"])
            .arg(self.o.config())
            .arg("-D")
            .arg(self.o.workdir())
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::process::CommandExt;
            let supervisor = std::process::id() as libc::pid_t;
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != supervisor {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        let child = command.spawn()
            .with_context(|| format!("starting {}", self.o.singbox.display()))?;
        self.child = Some(child);
        Ok(())
    }

    fn stop_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn failed(&mut self, error: anyhow::Error) -> anyhow::Error {
        self.stop_child();
        sysdns::restore();
        self.status("failed", &format!("{error:#}"));
        error
    }

    fn reload(&mut self) -> Result<()> {
        #[cfg(unix)]
        if let Some(child) = &mut self.child {
            if child.try_wait()?.is_none() {
                unsafe {
                    libc::kill(child.id() as libc::pid_t, libc::SIGHUP);
                }
                return Ok(());
            }
        }
        self.stop_child();
        self.start()
    }

    /// Why we should stop now, if we should. Only existence and timestamps of user files are consulted.
    fn stop_reason(&self) -> Option<String> {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Some("interrupted".into());
        }
        if fs::symlink_metadata(&self.o.stop_file).is_ok() {
            return Some("stopped by the app".into());
        }
        if self.o.connection_id.as_ref().is_some_and(|id| {
            crate::fsguard::read_regular_file(&self.o.stop_file.with_file_name("connection-id"), 128)
                .ok().as_deref() != Some(id.as_bytes())
        }) {
            return Some("the connection was replaced".into());
        }
        if fs::symlink_metadata(&self.o.client_config).is_err() {
            return Some("config removed (signed out or no exit assigned)".into());
        }
        if let Some((hb, max_age)) = &self.o.heartbeat {
            let stale = match mtime(hb) {
                Some(t) => SystemTime::now().duration_since(t).unwrap_or_default() > *max_age,
                None => true,
            };
            if stale {
                return Some("the app stopped sending heartbeats".into());
            }
        }
        None
    }
}

/// Run until told to stop. Returns Err only when sing-box cannot be kept running.
pub fn run(o: Options) -> Result<()> {
    runtime::prepare_protected_dir(&o.runtime_dir, o.require_privileged)?;
    let lock_path = o.runtime_dir.join("tunnel.lock");
    runtime::clean_protected_file(&lock_path, o.require_privileged)?;
    let _lock = session::try_lock(&lock_path)?.context("another tunnel supervisor is running on this host")?;
    let mut s = Supervisor { o, child: None, restarts: Vec::new(), route_generation: 0, running: None };
    if let Some(reason) = s.stop_reason() {
        s.status("stopped", &reason);
        return Ok(());
    }
    s.status("starting", "");
    // The version being loaded; anything written after this point is picked up by the loop, including changes
    // made while the DNS settle below is still waiting.
    let mut seen = mtime(&s.o.client_config);
    if let Err(e) = s.load().and_then(|_| s.start()) {
        s.status("failed", &format!("{e:#}"));
        return Err(e);
    }
    if let Err(error) = s.publish_ready_routes("") {
        return Err(s.failed(error));
    }

    loop {
        std::thread::sleep(s.o.poll);
        if let Some(reason) = s.stop_reason() {
            s.stop_child();
            sysdns::restore();
            s.status("stopped", &reason);
            return Ok(());
        }
        let current = mtime(&s.o.client_config);
        if current != seen {
            seen = current;
            match s.load() {
                Ok(true) => {
                    s.status("starting", "reloading the tunnel configuration");
                    if let Err(error) = s.reload() {
                        return Err(s.failed(error));
                    }
                    if let Err(error) = s.publish_ready_routes("config reloaded") {
                        return Err(s.failed(error));
                    }
                }
                Ok(false) => {}
                Err(e) => s.status("running", &format!("new config rejected, still on the previous one: {e:#}")),
            }
        }
        let exited = match s.child.as_mut().map(|c| c.try_wait()) {
            Some(Ok(Some(code))) => Some(code.to_string()),
            Some(Err(e)) => Some(e.to_string()),
            _ => None,
        };
        if let Some(code) = exited {
            s.child = None;
            let cutoff = Instant::now() - Duration::from_secs(60);
            s.restarts.retain(|t| *t > cutoff);
            if s.restarts.len() >= MAX_RESTARTS {
                let msg = format!("sing-box keeps exiting ({code}); see {}", s.o.log().display());
                sysdns::restore();
                s.status("failed", &msg);
                return Err(anyhow!(msg));
            }
            s.restarts.push(Instant::now());
            s.status("starting", "restarting the tunnel");
            if let Err(error) = s.start() {
                return Err(s.failed(error));
            }
            if let Err(error) = s.publish_ready_routes(&format!("sing-box exited ({code}) and was restarted")) {
                return Err(s.failed(error));
            }
        }
    }
}
