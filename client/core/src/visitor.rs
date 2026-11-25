//! The XTCP visitor (issue #61): frpc on the user's machine, so a customer whose exit host sits behind NAT needs no
//! manual frpc.
//!
//! When the user's exit host uses the XTCP transport, its sing-box entry is reached through frp: frpc on this
//! machine (the visitor) listens on 127.0.0.1:<entry port>, which is what the sing-box client config dials, and
//! punches a direct UDP path to the exit host's frpc. frps only brokers the rendezvous; there is no relay fallback.
//!
//! Pieces, all unprivileged (the visitor needs no privileges, so the root supervisor never runs frpc):
//!
//! * [`sync_visitor`] fetches `GET /v1/xtcp-visitor` (ETag polling, next to the sing-box config) and keeps the
//!   visitor files in the state directory: the frpc configuration this module renders from validated fields, the
//!   frps CA and the frps token, each mode 0600. 204 (public-entry host) removes them; so do sign-out and a 401.
//! * [`run_guard`] is `ccproxy visitor`: it owns one frpc process, passes the token through frpc's environment
//!   (never the command line), classifies frpc's log into a status file and stops frpc when its stdin closes (the
//!   app is gone, even after a crash), when the configuration is removed, or when frpc fails. On Windows frpc also
//!   sits in a kill-on-close job object, on Linux it gets a parent-death signal.
//! * [`VisitorProcess`] is the app side: it starts the guard once the tunnel runs, replaces it when the
//!   TUN routes or visitor configuration change, and stops it on disconnect,
//!   sign-out and exit. Nothing restarts in a tight loop.
//!
//! Start order: the supervisor brings the TUN up first, then frpc starts. With auto_route, frpc's own packets pass
//! through sing-box's direct outbound; a path punched before the TUN existed would change its source port and break.

use crate::api::{Api, VisitorFetch};
use crate::session::{self, write_atomic, Paths, Session};
use crate::supervisor::Status;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The only address the visitor listens on; the sing-box client config must dial it.
pub const BIND_ADDR: &str = "127.0.0.1";
/// How long an exited frpc that could not reach frps waits before the next attempt.
pub const UNREACHABLE_RETRY: Duration = Duration::from_secs(60);
const MAX_LOG_BYTES: u64 = 1 << 20;

/// What `GET /v1/xtcp-visitor` returns. Every field is validated before it reaches a file frpc reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisitorSpec {
    pub server_addr: String,
    pub server_port: u16,
    pub tls_server_name: String,
    pub ca_pem: String,
    pub auth_token: String,
    pub proxy_name: String,
    pub secret_key: String,
    pub bind_addr: String,
    pub bind_port: u16,
    #[serde(default)]
    pub exit_state: String,
}

/// The part of the spec kept for display: no credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisitorInfo {
    pub proxy_name: String,
    pub bind_port: u16,
    pub exit_state: String,
}

fn host_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !h.starts_with(['.', '-'])
}

fn secret_ok(s: &str) -> bool {
    (16..=256).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.~+/=-".contains(&b))
}

fn name_ok(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn ca_ok(pem: &str) -> bool {
    let t = pem.trim();
    pem.len() <= 64 << 10
        && t.starts_with("-----BEGIN CERTIFICATE-----")
        && t.ends_with("-----END CERTIFICATE-----")
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=- \r\n".contains(&b))
}

impl VisitorSpec {
    /// The same rules the control plane applies, checked again here: frpc renders its configuration as a Go template
    /// and the values go into TOML strings, so nothing outside these character sets may reach the file.
    pub fn validate(&self) -> Result<()> {
        if !host_ok(&self.server_addr) {
            bail!("visitor: server_addr is not a host name or IPv4 address");
        }
        if self.server_port == 0 {
            bail!("visitor: server_port out of range");
        }
        if !host_ok(&self.tls_server_name) {
            bail!("visitor: tls_server_name is not a host name");
        }
        if !ca_ok(&self.ca_pem) {
            bail!("visitor: ca_pem is not PEM certificates");
        }
        if !secret_ok(&self.auth_token) {
            bail!("visitor: auth_token is malformed");
        }
        if !secret_ok(&self.secret_key) {
            bail!("visitor: secret_key is malformed");
        }
        if !name_ok(&self.proxy_name) {
            bail!("visitor: proxy_name is malformed");
        }
        if self.bind_addr != BIND_ADDR {
            bail!("visitor: bind_addr must be {BIND_ADDR}");
        }
        if self.bind_port == 0 {
            bail!("visitor: bind_port out of range");
        }
        Ok(())
    }

    pub fn info(&self) -> VisitorInfo {
        VisitorInfo { proxy_name: self.proxy_name.clone(), bind_port: self.bind_port, exit_state: self.exit_state.clone() }
    }
}

/// A TOML basic string. The value must not contain a Go template action, since frpc renders the file first.
fn toml_string(value: &str) -> Result<String> {
    if value.contains("{{") || value.contains("}}") || value.chars().any(|c| c.is_control()) {
        bail!("visitor: {value:?} cannot appear in the frpc configuration");
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// The visitor's frpc configuration. The token is not in it: frpc reads FRP_AUTH_TOKEN from its environment.
/// keepTunnelOpen makes frpc punch at once (and keep the path open), so readiness and a failed punch show up before
/// the first connection; it retries at most 8 times an hour, never through a relay.
pub fn render_toml(spec: &VisitorSpec, ca_file: &Path) -> Result<String> {
    spec.validate()?;
    Ok(format!(
        r#"# frpc XTCP visitor written by the aifree app. Direct connections only: there is no relay fallback.
serverAddr = "{server}"
serverPort = {server_port}
loginFailExit = true
auth.method = "token"
auth.token = "{{{{ .Envs.FRP_AUTH_TOKEN }}}}"
transport.tls.enable = true
transport.tls.trustedCaFile = {ca}
transport.tls.serverName = "{tls}"
log.to = "console"
log.level = "info"

[[visitors]]
name = "{proxy}-visitor"
type = "xtcp"
serverName = "{proxy}"
secretKey = "{secret}"
bindAddr = "{bind_addr}"
bindPort = {bind_port}
protocol = "quic"
keepTunnelOpen = true
maxRetriesAnHour = 8
minRetryInterval = 90
"#,
        server = spec.server_addr,
        server_port = spec.server_port,
        ca = toml_string(&ca_file.display().to_string())?,
        tls = spec.tls_server_name,
        proxy = spec.proxy_name,
        secret = spec.secret_key,
        bind_addr = spec.bind_addr,
        bind_port = spec.bind_port,
    ))
}

// ---- files --------------------------------------------------------------------------------------------------

/// Every visitor file in the state directory, for removal with the session.
pub fn files(paths: &Paths) -> Vec<PathBuf> {
    vec![
        paths.visitor_toml(),
        paths.visitor_ca(),
        paths.visitor_token(),
        paths.visitor_info(),
        paths.visitor_etag(),
        paths.visitor_status(),
        paths.visitor_log(),
    ]
}

/// Remove the visitor configuration (not the guard's status or log). The guard stops when its configuration goes.
pub(crate) fn remove_config_files(paths: &Paths) {
    for p in [paths.visitor_toml(), paths.visitor_ca(), paths.visitor_token(), paths.visitor_info(), paths.visitor_etag()] {
        let _ = fs::remove_file(p);
    }
}

/// Whether the current session needs a visitor (its exit host uses XTCP).
pub fn required(paths: &Paths) -> bool {
    paths.visitor_toml().exists()
}

/// Identifies what frpc runs: its configuration, the CA and the token. None when no visitor is configured.
pub fn fingerprint(paths: &Paths) -> Option<String> {
    let mut h = Sha256::new();
    for p in [paths.visitor_toml(), paths.visitor_ca(), paths.visitor_token()] {
        h.update(fs::read(p).ok()?);
        h.update([0]);
    }
    Some(format!("{:x}", h.finalize())[..32].to_string())
}

pub fn read_info(paths: &Paths) -> Option<VisitorInfo> {
    serde_json::from_slice(&fs::read(paths.visitor_info()).ok()?).ok()
}

/// Write the visitor files for `spec`. Only files whose content changed are replaced.
fn write_files(paths: &Paths, spec: &VisitorSpec) -> Result<()> {
    let toml = render_toml(spec, &paths.visitor_ca())?;
    let ca = spec.ca_pem.trim().to_string() + "\n";
    for (path, data) in [
        (paths.visitor_ca(), ca.as_bytes()),
        (paths.visitor_token(), spec.auth_token.as_bytes()),
        (paths.visitor_toml(), toml.as_bytes()),
    ] {
        if fs::read(&path).ok().as_deref() != Some(data) {
            write_atomic(&path, data, true)?;
        }
    }
    write_atomic(&paths.visitor_info(), &serde_json::to_vec(&spec.info())?, true)
}

// ---- sync ---------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum VisitorSync {
    /// The visitor files were written or replaced.
    Updated,
    Unchanged,
    /// The exit host uses the public entry: no visitor; any visitor files were removed.
    NotNeeded,
    /// The token is no longer valid; the session and every derived file were removed.
    SignedOut,
    /// The control plane cannot give this device a visitor (409): carries its message. Visitor files were removed.
    Unavailable(String),
    /// The control plane predates `/v1/xtcp-visitor` (404). No visitor is run (any visitor files were removed); the
    /// tunnel works as before: directly on a public-entry host, through a hand-run visitor on an XTCP host.
    Unsupported,
    /// The session changed while the request was in flight; the reply was dropped.
    Superseded,
}

/// One poll of `GET /v1/xtcp-visitor`, applied under [`session::lock`] only if `session` is still current.
pub fn sync_visitor(paths: &Paths, session: &Session) -> Result<VisitorSync> {
    let api = Api::new(&session.server)?;
    let etag = if paths.visitor_toml().exists() { session::read_file_trimmed(&paths.visitor_etag()) } else { None };
    let reply = api.xtcp_visitor(&session.token, etag.as_deref())?;
    let _g = session::lock();
    if !Session::is_current(paths, &session.id) {
        return Ok(VisitorSync::Superseded);
    }
    match reply {
        VisitorFetch::NotModified => Ok(VisitorSync::Unchanged),
        VisitorFetch::NotNeeded => {
            remove_config_files(paths);
            Ok(VisitorSync::NotNeeded)
        }
        VisitorFetch::Unauthorized => {
            Session::clear_locked(paths);
            Ok(VisitorSync::SignedOut)
        }
        VisitorFetch::Unavailable(msg) => {
            remove_config_files(paths);
            Ok(VisitorSync::Unavailable(msg))
        }
        VisitorFetch::Unsupported => {
            remove_config_files(paths);
            Ok(VisitorSync::Unsupported)
        }
        VisitorFetch::Changed { etag, body } => {
            let spec: VisitorSpec = serde_json::from_slice(&body).context("visitor settings are not valid JSON")?;
            spec.validate()?;
            write_files(paths, &spec)?;
            write_atomic(&paths.visitor_etag(), etag.as_bytes(), false)?;
            Ok(VisitorSync::Updated)
        }
    }
}

/// The sing-box client config must dial the visitor: server 127.0.0.1 and the visitor's port.
pub fn check_entry(paths: &Paths) -> Result<()> {
    let Some(info) = read_info(paths) else { return Ok(()) };
    let config: serde_json::Value = serde_json::from_slice(&fs::read(paths.config()).context("reading the tunnel config")?)?;
    let server = config.pointer("/outbounds/0/server").and_then(|v| v.as_str()).unwrap_or_default();
    let port = config.pointer("/outbounds/0/server_port").and_then(|v| v.as_u64()).unwrap_or_default();
    if server != BIND_ADDR || port != u64::from(info.bind_port) {
        bail!("the tunnel config dials {server}:{port}, but the XTCP visitor listens on {BIND_ADDR}:{}; ask the admin \
               to set the exit host's public entry address to {BIND_ADDR}", info.bind_port);
    }
    Ok(())
}

// ---- status -------------------------------------------------------------------------------------------------

/// Why the visitor failed. Each has its own message ([`Reason::message`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    ServerUnreachable,
    TokenRefused,
    CertificateRejected,
    ExitNotOnline,
    HolePunchFailed,
    LocalPortBusy,
    FrpcExited,
    FrpcMissing,
}

impl Reason {
    pub fn message(self, detail: &str, port: u16) -> String {
        let detail = if detail.is_empty() { String::new() } else { format!(" ({detail})") };
        match self {
            Reason::ServerUnreachable => format!("Could not reach the XTCP rendezvous server (frps){detail}. The app tries again in a minute."),
            Reason::TokenRefused => format!("The XTCP rendezvous server refused the access token{detail}. If the administrator rotated it, the app reconnects once it receives the new one."),
            Reason::CertificateRejected => format!("The XTCP rendezvous server's certificate is not signed by the expected CA{detail}."),
            Reason::ExitNotOnline => format!("Your exit host is not registered with the XTCP rendezvous server; it may be offline{detail}."),
            Reason::HolePunchFailed => format!("Could not open a direct connection to your exit host (hole punching failed){detail}. Traffic is never relayed; frpc retries at most 8 times an hour."),
            Reason::LocalPortBusy => format!("Local port {port} is already in use by another program, so the XTCP visitor cannot listen on it{detail}."),
            Reason::FrpcExited => format!("The XTCP visitor (frpc) stopped unexpectedly{detail}."),
            Reason::FrpcMissing => format!("The XTCP visitor (frpc) could not be started{detail}."),
        }
    }
}

/// Written by the guard into the state directory. No credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisitorStatus {
    /// starting | listening | ready | failed | stopped
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    pub message: String,
    pub updated: u64,
    /// [`fingerprint`] of the configuration this guard runs.
    pub fingerprint: String,
    /// Pid of the guard that wrote it. A connection trusts only the status of the guard it started itself, never one a
    /// previous connection or app run left behind.
    #[serde(default)]
    pub guard: u32,
}

pub fn read_status(paths: &Paths) -> Option<VisitorStatus> {
    serde_json::from_slice(&fs::read(paths.visitor_status()).ok()?).ok()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What the app shows for the tunnel while a visitor is required and the supervisor runs: (state, message), with
/// state "running" only once the visitor listens and the first direct path to the exit host is open.
///
/// `guard` is the guard this connection started ([`VisitorProcess::guard_pid`]). Only a status that guard wrote, for
/// the current configuration, counts; without a guard of its own the connection is still starting, whatever status a
/// previous connection left behind.
pub fn tunnel_view(paths: &Paths, guard: Option<u32>) -> Option<(String, String)> {
    let fp = fingerprint(paths)?;
    let info = read_info(paths);
    let port = info.as_ref().map(|i| i.bind_port).unwrap_or_default();
    let waiting = |what: &str| {
        let mut m = what.to_string();
        if let Some(i) = info.as_ref().filter(|i| !i.exit_state.is_empty() && i.exit_state != "ready") {
            m.push_str(&format!(" Your exit host has not confirmed its XTCP mapping yet ({}).", i.exit_state));
        }
        ("connecting".to_string(), m)
    };
    let status = guard.and_then(|g| read_status(paths).filter(|s| s.fingerprint == fp && s.guard == g));
    Some(match status {
        None => waiting("Starting the XTCP visitor."),
        Some(s) => match s.state.as_str() {
            "ready" => ("running".into(), String::new()),
            "starting" => waiting("Connecting to the XTCP rendezvous server."),
            "listening" => waiting("Opening a direct connection to your exit host."),
            "failed" => ("failed".into(), s.message),
            _ => ("failed".into(), orelse(s.message, || Reason::FrpcExited.message("", port))),
        },
    })
}

fn orelse(s: String, f: impl FnOnce() -> String) -> String {
    if s.is_empty() { f() } else { s }
}

// ---- frpc log classification --------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Logged in to frps and listening on the local port.
    Listening,
    /// A direct path to the exit host is open.
    Ready,
    /// frpc cannot work with this configuration; the guard stops it.
    Fatal(Reason, String),
    /// A hole-punching attempt failed; frpc keeps running and retries on its own (bounded).
    PunchFailed(Reason, String),
}

fn after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.find(key).map(|i| line[i + key.len()..].trim())
}

fn short(detail: &str) -> String {
    let d = detail.trim().trim_end_matches('.');
    if d.chars().count() > 200 { d.chars().take(200).collect::<String>() + "…" } else { d.to_string() }
}

/// Classify one line of frpc 0.72.0 output (log.to = console, info level). Texts are taken from frp's sources
/// (client/service.go, client/visitor/*.go, pkg/auth/token.go, pkg/nathole/controller.go).
pub fn classify(line: &str) -> Option<Event> {
    if line.contains("start visitor success") {
        return Some(Event::Listening);
    }
    if line.contains("establishing nat hole connection successful") {
        return Some(Event::Ready);
    }
    if let Some(d) = after(line, "start error:") {
        let lower = d.to_ascii_lowercase();
        if lower.contains("address already in use") || lower.contains("only one usage of each socket address")
            || lower.contains("access permissions") {
            return Some(Event::Fatal(Reason::LocalPortBusy, short(d)));
        }
        return Some(Event::Fatal(Reason::FrpcExited, short(d)));
    }
    let login = after(line, "connect to server error:").or_else(|| after(line, "login to the server failed:"));
    if let Some(d) = login {
        let d = d.split(". With loginFailExit").next().unwrap_or(d);
        let lower = d.to_ascii_lowercase();
        let reason = if lower.contains("token in login doesn't match") || lower.contains("authorization failed") {
            Reason::TokenRefused
        } else if lower.contains("x509") || lower.contains("certificate") || lower.contains("tls:") {
            Reason::CertificateRejected
        } else {
            Reason::ServerUnreachable
        };
        return Some(Event::Fatal(reason, short(d)));
    }
    for key in ["nathole exchange info error:", "nathole prepare error:", "nathole precheck error:", "make hole error:",
                "keepTunnelOpenWorker get tunnel connection error:", "open tunnel error:", "init tunnel session error:"] {
        if let Some(d) = after(line, key) {
            let reason = if d.contains("doesn't exist") { Reason::ExitNotOnline } else { Reason::HolePunchFailed };
            return Some(Event::PunchFailed(reason, short(d)));
        }
    }
    None
}

// ---- the guard (`ccproxy visitor`) --------------------------------------------------------------------------

struct Guard<'a> {
    paths: &'a Paths,
    fingerprint: String,
    secrets: Vec<String>,
}

impl Guard<'_> {
    fn status(&self, state: &str, reason: Option<Reason>, message: &str) {
        let s = VisitorStatus { state: state.into(), reason, message: self.redact(message), updated: now(),
                                fingerprint: self.fingerprint.clone(), guard: std::process::id() };
        if let Ok(data) = serde_json::to_vec_pretty(&s) {
            let _ = write_atomic(&self.paths.visitor_status(), &data, true);
        }
    }

    fn redact(&self, text: &str) -> String {
        let mut t = text.to_string();
        for s in &self.secrets {
            if !s.is_empty() {
                t = t.replace(s.as_str(), "[redacted]");
            }
        }
        t
    }
}

fn secret_key_of(toml: &str) -> Option<String> {
    toml.lines().find_map(|l| l.strip_prefix("secretKey = \"")).map(|v| v.trim_end_matches('"').to_string())
}

/// Spawn frpc so that it cannot outlive the guard where the OS allows it.
fn spawn_frpc(frpc: &Path, paths: &Paths, token: &str) -> Result<Child> {
    let mut cmd = Command::new(frpc);
    cmd.arg("-c").arg(paths.visitor_toml())
        .current_dir(&paths.dir)
        .env("FRP_AUTH_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(windows_job::CREATE_NO_WINDOW);
    }
    let child = cmd.spawn().with_context(|| format!("starting {}", frpc.display()))?;
    #[cfg(windows)]
    windows_job::kill_on_close(&child)?;
    Ok(child)
}

fn terminate(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// `ccproxy visitor`: run frpc for the visitor files in `paths` until stdin closes, the configuration is removed or
/// frpc fails. Never retries by itself; the app decides (see [`VisitorProcess`]).
pub fn run_guard(paths: &Paths, frpc: &Path, stdin_eof: Arc<AtomicBool>) -> Result<()> {
    ensure_unprivileged()?;
    let fingerprint = fingerprint(paths).ok_or_else(|| anyhow!("no XTCP visitor is configured"))?;
    let token = fs::read_to_string(paths.visitor_token())?.trim().to_string();
    let toml = fs::read_to_string(paths.visitor_toml())?;
    let port = read_info(paths).map(|i| i.bind_port).unwrap_or_default();
    let g = Guard { paths, fingerprint, secrets: vec![token.clone(), secret_key_of(&toml).unwrap_or_default()] };
    g.status("starting", None, "");

    let mut log = fs::OpenOptions::new().create(true).write(true).truncate(true).open(paths.visitor_log())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        log.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let mut child = match spawn_frpc(frpc, paths, &token) {
        Ok(c) => c,
        Err(e) => {
            g.status("failed", Some(Reason::FrpcMissing), &Reason::FrpcMissing.message(&format!("{e:#}"), port));
            return Err(e);
        }
    };
    write_pidfile(paths, child.id());

    let (tx, rx) = mpsc::channel::<String>();
    for out in [child.stdout.take().map(|o| Box::new(o) as Box<dyn Read + Send>),
                child.stderr.take().map(|e| Box::new(e) as Box<dyn Read + Send>)].into_iter().flatten() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut state = "starting";
    let mut written: u64 = 0;
    let mut last_failure: Option<(Reason, String)> = None;
    let outcome: Result<()> = loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let line = g.redact(&line);
                if written < MAX_LOG_BYTES {
                    written += line.len() as u64 + 1;
                    let _ = writeln!(log, "{line}");
                }
                match classify(&line) {
                    Some(Event::Listening) if state != "ready" => {
                        state = "listening";
                        g.status(state, None, "");
                    }
                    Some(Event::Ready) => {
                        state = "ready";
                        last_failure = None;
                        g.status(state, None, "");
                    }
                    Some(Event::Fatal(reason, detail)) => {
                        let message = reason.message(&detail, port);
                        g.status("failed", Some(reason), &message);
                        terminate(&mut child);
                        break Err(anyhow!(message));
                    }
                    Some(Event::PunchFailed(reason, detail)) => {
                        state = "failed";
                        g.status(state, Some(reason), &reason.message(&detail, port));
                        last_failure = Some((reason, detail));
                    }
                    _ => {}
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // frpc closed its output: it has exited (or is about to).
                let code = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                let (reason, detail) = last_failure.clone().unwrap_or((Reason::FrpcExited, code));
                let message = reason.message(&detail, port);
                g.status("failed", Some(reason), &message);
                break Err(anyhow!(message));
            }
        }
        if stdin_eof.load(Ordering::SeqCst) {
            terminate(&mut child);
            g.status("stopped", None, "stopped by the app");
            break Ok(());
        }
        if !paths.visitor_toml().exists() {
            terminate(&mut child);
            g.status("stopped", None, "the visitor configuration was removed");
            break Ok(());
        }
    };
    let _ = fs::remove_file(paths.visitor_pid());
    outcome
}

/// Set `flag` when stdin reaches EOF: the process that started the guard closed it or is gone.
pub fn watch_stdin(flag: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        flag.store(true, Ordering::SeqCst);
    });
}

// ---- the app side -------------------------------------------------------------------------------------------

/// Where the two sidecars are.
#[derive(Debug, Clone)]
pub struct Launcher {
    /// `ccproxy` (runs the guard).
    pub ccproxy: PathBuf,
    pub frpc: PathBuf,
}

#[derive(PartialEq, Eq)]
struct VisitorTarget {
    fingerprint: String,
    route: (u32, u64),
}

/// The app's handle on the guard. Dropping it stops the visitor.
#[derive(Default)]
pub struct VisitorProcess {
    guard: Option<(Child, ChildStdin, VisitorTarget)>,
    /// The last failed visitor and its route, so the same failure is not retried in a loop.
    exited: Option<(VisitorTarget, Instant, Option<Reason>, u32)>,
}

impl VisitorProcess {
    /// Run exactly one visitor for the current configuration and live TUN routes. A prior UDP path
    /// can stop working when macOS installs new TUN routes, even if the visitor configuration is unchanged.
    pub fn ensure(&mut self, paths: &Paths, launcher: &Launcher, status: Option<&Status>) -> Result<()> {
        let target = status.and_then(Status::running_route).and_then(|route| {
            fingerprint(paths).map(|fingerprint| VisitorTarget { fingerprint, route })
        });
        let Some(target) = target else {
            self.stop();
            return Ok(());
        };
        if let Some((child, _, running)) = self.guard.as_mut() {
            match child.try_wait() {
                Ok(None) if *running == target => return Ok(()),
                Ok(None) => self.stop(),
                _ => {
                    if let Some((child, _, running)) = self.guard.take() {
                        let pid = child.id();
                        let reason = read_status(paths)
                            .filter(|s| s.fingerprint == running.fingerprint && s.guard == pid)
                            .and_then(|s| s.reason);
                        self.exited = Some((running, Instant::now(), reason, pid));
                    }
                }
            }
        }
        if let Some((failed, at, reason, _)) = &self.exited {
            let retry = *reason == Some(Reason::ServerUnreachable) && at.elapsed() >= UNREACHABLE_RETRY;
            if *failed == target && !retry {
                return Ok(());
            }
        }
        self.start(paths, launcher, target)
    }

    /// Forget a failed configuration so the next [`ensure`](Self::ensure) tries again (a new Connect).
    pub fn reset(&mut self) {
        self.exited = None;
    }

    /// The guard for these TUN routes, including its last failed attempt for error reporting.
    pub fn guard_pid(&self, status: Option<&Status>) -> Option<u32> {
        let route = status?.running_route()?;
        match (&self.guard, &self.exited) {
            (Some((child, _, target)), _) if target.route == route => Some(child.id()),
            (None, Some((target, _, _, pid))) if target.route == route => Some(*pid),
            _ => None,
        }
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.guard.as_mut().map(|(c, _, _)| c.try_wait()), Some(Ok(None)))
    }

    fn start(&mut self, paths: &Paths, launcher: &Launcher, target: VisitorTarget) -> Result<()> {
        kill_stale(paths);
        let _ = fs::remove_file(paths.visitor_status());
        let mut cmd = Command::new(&launcher.ccproxy);
        cmd.arg("--state-dir").arg(&paths.dir).arg("visitor").arg("--frpc").arg(&launcher.frpc)
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(windows_job::CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().with_context(|| format!("starting {}", launcher.ccproxy.display()))?;
        let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin for the visitor guard"))?;
        self.exited = None;
        self.guard = Some((child, stdin, target));
        Ok(())
    }

    /// Stop the guard (closing its stdin stops frpc), waiting briefly before killing it.
    pub fn stop(&mut self) {
        self.exited = None;
        if let Some((mut child, stdin, _)) = self.guard.take() {
            drop(stdin);
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for VisitorProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Refuse root (Unix) and Administrator (Windows): the visitor reads its configuration from the user's state
/// directory, which a privileged process must never consume without the supervisor's validation boundary. The
/// desktop app and `ccproxy headless` run as the signed-in user; `ccproxy up` (root) runs no visitor.
pub fn ensure_unprivileged() -> Result<()> {
    if running_privileged() {
        bail!("the XTCP visitor must not run as root or Administrator; run it as the signed-in user");
    }
    Ok(())
}

#[cfg(unix)]
fn running_privileged() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn running_privileged() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

/// What the guard records about the frpc it runs, so a later cleanup can tell its own orphan from a live visitor and
/// from an unrelated process that reused the pid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrpcRecord {
    pub frpc: u32,
    pub guard: u32,
    /// [`process_identity`] of frpc right after it started: start time and command line.
    pub identity: String,
}

fn write_pidfile(paths: &Paths, frpc: u32) {
    // Without an identity no later cleanup could prove ownership, so record nothing rather than a bare pid.
    let Some(identity) = process_identity(frpc) else { return };
    let record = FrpcRecord { frpc, guard: std::process::id(), identity };
    if let Ok(data) = serde_json::to_vec(&record) {
        let _ = write_atomic(&paths.visitor_pid(), &data, true);
    }
}

fn read_pidfile(paths: &Paths) -> Option<FrpcRecord> {
    serde_json::from_slice::<FrpcRecord>(&fs::read(paths.visitor_pid()).ok()?).ok()
        .filter(|r| r.frpc > 1 && r.guard > 1 && !r.identity.is_empty())
}

/// A process's identity: its start time and full command line, as `ps` reports them (Unix). None where it cannot be
/// read, including on Windows, where the guard's kill-on-close job object already ends frpc with its guard.
pub fn process_identity(pid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let out = Command::new("ps").env("LC_ALL", "C").args(["-p", &pid.to_string(), "-o", "lstart=", "-o", "command="])
            .output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !text.is_empty()).then_some(text)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true // unknown: treat as present, so nothing is removed or signalled
    }
}

/// Kill an frpc that a killed guard left behind (on macOS frpc cannot be tied to the guard's lifetime). It fails closed:
/// a process is signalled only when all of these hold, else it is left alone.
///
/// * The pid file names frpc, its guard and frpc's identity (start time and command line).
/// * The process now at that pid has exactly that identity, so a pid reused by an unrelated process, even one named
///   frpc, does not match. An identity that cannot be read means no signal.
/// * Its guard is gone: no `ccproxy` process at the guard's pid, and frpc is no longer its child. A visitor whose guard
///   still runs, such as the one of an app instance that is already connected, is not an orphan.
///
/// Call it only from the process that owns the session (the primary app instance).
pub fn kill_stale(paths: &Paths) {
    let Some(record) = read_pidfile(paths) else { return };
    if !process_exists(record.frpc) {
        let _ = fs::remove_file(paths.visitor_pid()); // frpc is gone: nothing to clean up
        return;
    }
    match process_identity(record.frpc) {
        Some(now) if now == record.identity => {}
        Some(_) => {
            // The pid now belongs to another process (reused): it is not ours, and the record is stale.
            let _ = fs::remove_file(paths.visitor_pid());
            return;
        }
        None => return, // cannot establish ownership
    }
    if !is_named(record.frpc, "frpc") || is_named(record.guard, "ccproxy") || parent_of(record.frpc) == Some(record.guard) {
        return; // not frpc, or a live visitor
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(record.frpc as libc::pid_t, libc::SIGKILL);
    }
    let _ = fs::remove_file(paths.visitor_pid());
}

/// Whether `pid` runs an executable called `name` (`name.exe` on Windows).
fn is_named(pid: u32, name: &str) -> bool {
    #[cfg(unix)]
    let out = Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output();
    #[cfg(windows)]
    let out = Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"]).output();
    let want = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    out.map(|o| {
        let text = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
        text.lines().any(|l| {
            let exe = l.trim().trim_matches('"').split(['"', ',']).next().unwrap_or("");
            exe.rsplit(['/', '\\']).next() == Some(want.as_str())
        })
    })
    .unwrap_or(false)
}

/// The parent pid of `pid` (Unix); None where unknown.
fn parent_of(pid: u32) -> Option<u32> {
    #[cfg(unix)]
    {
        let out = Command::new("ps").args(["-p", &pid.to_string(), "-o", "ppid="]).output().ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

#[cfg(windows)]
mod windows_job {
    use anyhow::{bail, Result};
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Put `child` in a job that is killed when the guard's handle to it closes, i.e. when the guard exits for any
    /// reason. The handle is intentionally never closed by hand.
    pub fn kill_on_close(child: &Child) -> Result<()> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                bail!("CreateJobObjectW failed: {}", std::io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const _,
                                       std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32) == 0 {
                bail!("SetInformationJobObject failed: {}", std::io::Error::last_os_error());
            }
            if AssignProcessToJobObject(job, child.as_raw_handle() as _) == 0 {
                bail!("AssignProcessToJobObject failed: {}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
