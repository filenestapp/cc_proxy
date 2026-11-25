//! The aifree CLI signs in to the control plane and runs the tunnel from a terminal.
//!
//!   ccproxy login --server https://cp.example.com --user alice      (password from stdin or CCPROXY_PASSWORD)
//!   sudo ccproxy up                                                 (foreground: keeps config current, runs sing-box)
//!   ccproxy status | ccproxy logout
//!
//! `ccproxy tunnel` is the privileged half the desktop app launches through the OS authorisation prompt.
//! `ccproxy visitor` is the unprivileged XTCP visitor guard (frpc) the desktop app starts once the tunnel runs.
//! `ccproxy up --visitor` runs that same visitor for an exit host on XTCP; without it, a hand-run frpc is expected.

use anyhow::{anyhow, bail, Context, Result};
use ccproxy_core::api::Api;
use ccproxy_core::session::{Paths, Session};
use ccproxy_core::runtime;
use ccproxy_core::supervisor::{self, Status};
use ccproxy_core::sync::{sync_once, sync_with_visitor, SyncOutcome};
use ccproxy_core::visitor::{self, VisitorProcess};
use ccproxy_core::{default_device_name, platform, DEFAULT_MODE};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "ccproxy", version, about = "aifree command-line client")]
struct Cli {
    /// State directory (session, config, status). Default: the OS config dir + cc-proxy.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign in with a username and password; stores a device token (never the password).
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        user: String,
        /// Device name shown to the admin. Default: this computer's host name.
        #[arg(long)]
        device: Option<String>,
    },
    /// Show the session and the tunnel status.
    Status,
    /// Fetch the config once.
    Sync {
        #[arg(long, default_value = DEFAULT_MODE)]
        mode: String,
    },
    /// Run in the foreground: keep the config current and run sing-box (needs root / Administrator).
    Up {
        /// Seconds between config checks.
        #[arg(long, default_value_t = 30)]
        interval: u64,
        #[arg(long)]
        singbox: Option<PathBuf>,
        /// Run the XTCP visitor (frpc) when the exit host uses XTCP, instead of expecting a hand-run frpc.
        #[arg(long)]
        visitor: bool,
        /// frpc for --visitor. Default: next to this executable, else on PATH.
        #[arg(long)]
        frpc: Option<PathBuf>,
    },
    /// Sign out: revoke this device on the server and forget the session.
    Logout,
    /// Privileged supervisor started by the desktop app. Not meant to be run by hand.
    Tunnel {
        #[arg(long)]
        singbox: Option<PathBuf>,
        /// Stop when the app's heartbeat file is older than this many seconds (0: no heartbeat).
        #[arg(long, default_value_t = 30)]
        heartbeat_timeout: u64,
    },
    /// XTCP visitor guard started by the desktop app: runs frpc until stdin closes. Not meant to be run by hand.
    Visitor {
        #[arg(long)]
        frpc: Option<PathBuf>,
    },
}

/// sing-box next to this executable (how the desktop bundle ships it), else on PATH.
fn find_singbox(explicit: Option<PathBuf>) -> PathBuf {
    find_sidecar(explicit, "sing-box")
}

/// A sidecar binary next to this executable, else its bare name (looked up on PATH).
fn find_sidecar(explicit: Option<PathBuf>, base: &str) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    let name = if cfg!(windows) { format!("{base}.exe") } else { base.to_string() };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(&name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(name)
}

fn read_password() -> Result<String> {
    if let Ok(pw) = std::env::var("CCPROXY_PASSWORD") {
        return Ok(pw);
    }
    eprint!("password: ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn options(paths: &Paths, singbox: PathBuf, heartbeat: Option<u64>) -> supervisor::Options {
    supervisor::Options {
        singbox,
        client_config: paths.config(),
        stop_file: paths.stop(),
        heartbeat: heartbeat.filter(|s| *s > 0).map(|s| (paths.heartbeat(), Duration::from_secs(s))),
        poll: Duration::from_millis(500),
        runtime_dir: runtime::protected_dir(),
        require_privileged: true,
    }
}

fn require_session(paths: &Paths) -> Result<Session> {
    Session::load(paths).ok_or_else(|| anyhow!("not signed in; run `ccproxy login` first"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::new(cli.state_dir.clone())?;
    match cli.cmd {
        Cmd::Login { server, user, device } => {
            let api = Api::new(&server)?;
            let device = device.unwrap_or_else(default_device_name);
            let password = read_password()?;
            let resp = api.login(&user, &password, &device, platform()).map_err(|e| anyhow!("{e}"))?;
            Session::new(api.base().to_string(), resp.user.clone(), resp.device.clone(), resp.token)
                .save(&paths)?;
            match resp.entry {
                Some(e) => println!("signed in as {} on {}; exit IP {}, entry {}:{}", resp.user, resp.device,
                                    resp.egress_ip.unwrap_or_default(), e.host, e.port),
                None => println!("signed in as {} on {}; no exit assigned yet", resp.user, resp.device),
            }
        }
        Cmd::Status => {
            match Session::load(&paths) {
                None => println!("not signed in"),
                Some(s) => {
                    println!("signed in as {} on {} ({})", s.user, s.device, s.server);
                    match Api::new(&s.server)?.me(&s.token) {
                        Ok(Some(me)) => match me.entry {
                            Some(e) => println!("exit IP {} via {}:{}", me.egress_ip.unwrap_or_default(), e.host, e.port),
                            None => println!("no exit assigned"),
                        },
                        Ok(None) => println!("session is no longer valid (signed out elsewhere or revoked)"),
                        Err(e) => println!("control plane unreachable: {e}"),
                    }
                }
            }
            match Status::current() {
                Some(st) => println!("tunnel: {} {}", st.state, st.message),
                None => println!("tunnel: never started"),
            }
            if visitor::required(&paths) {
                match visitor::read_status(&paths) {
                    Some(v) => println!("xtcp visitor: {} {}", v.state, v.message),
                    None => println!("xtcp visitor: not running"),
                }
            }
        }
        Cmd::Sync { mode } => {
            let s = require_session(&paths)?;
            println!("{:?}", sync_once(&paths, &s, &mode)?);
        }
        Cmd::Logout => {
            if let Some(s) = Session::load(&paths) {
                if let Err(e) = Api::new(&s.server)?.logout(&s.token) {
                    eprintln!("warning: server sign-out failed ({e}); forgetting the session locally");
                }
            }
            Session::clear(&paths);
            println!("signed out");
        }
        Cmd::Tunnel { singbox, heartbeat_timeout } => {
            supervisor::install_signal_handlers();
            supervisor::run(options(&paths, find_singbox(singbox), Some(heartbeat_timeout)))?;
        }
        Cmd::Visitor { frpc } => {
            let eof = Arc::new(AtomicBool::new(false));
            visitor::watch_stdin(eof.clone());
            visitor::run_guard(&paths, &find_sidecar(frpc, "frpc"), eof)?;
        }
        Cmd::Up { interval, singbox, visitor, frpc } => {
            let launcher = visitor.then(|| visitor::Launcher {
                ccproxy: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ccproxy")),
                frpc: find_sidecar(frpc, "frpc"),
            });
            up(&paths, DEFAULT_MODE, interval, find_singbox(singbox), launcher)?
        }
    }
    Ok(())
}

/// Headless client: poller on this thread, supervisor on another, sharing the state directory. With `launcher`
/// (`--visitor`), the XTCP visitor runs too: started once the supervisor reports the tunnel running, restarted when
/// its settings change, stopped on the way out.
fn up(paths: &Paths, mode: &str, interval: u64, singbox: PathBuf, launcher: Option<visitor::Launcher>) -> Result<()> {
    let session = require_session(paths)?;
    let sync = |paths: &Paths, session: &Session| {
        if launcher.is_some() { sync_with_visitor(paths, session, mode) } else { sync_once(paths, session, mode) }
    };
    match sync(paths, &session)? {
        SyncOutcome::SignedOut => bail!("session is no longer valid; sign in again"),
        SyncOutcome::Unassigned(msg) => bail!("{msg}"),
        SyncOutcome::XtcpUnavailable(msg) => bail!("XTCP visitor unavailable: {msg}"),
        _ => {}
    }
    if launcher.is_none() && visitor::required(paths) {
        println!("note: the exit host uses XTCP; run frpc yourself or pass --visitor");
    }
    let _ = std::fs::remove_file(paths.stop());
    supervisor::install_signal_handlers();
    let done = Arc::new(AtomicBool::new(false));
    let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let sup = {
        let (opts, done) = (options(paths, singbox, None), done.clone());
        std::thread::spawn(move || {
            let r = supervisor::run(opts);
            done.store(true, Ordering::SeqCst);
            r
        })
    };
    println!("tunnel up; checking for config changes every {interval}s (Ctrl-C to stop)");
    let mut proc = VisitorProcess::default();
    let mut shown = String::new();
    let mut next = Instant::now() + Duration::from_secs(interval);
    while !done.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(250));
        if let Some(launcher) = &launcher {
            // The TUN first, then frpc: its punched path must not move when the TUN takes over routing.
            let tunnel_running = Status::current().is_some_and(|s| s.state == "running" && s.updated >= started);
            if tunnel_running {
                if let Err(e) = proc.ensure(paths, launcher) {
                    eprintln!("could not start the XTCP visitor: {e:#}");
                }
            }
            if let Some((state, message)) = visitor::tunnel_view(paths) {
                let line = format!("xtcp visitor: {state} {message}");
                if line != shown {
                    println!("{line}");
                    shown = line;
                }
            }
        }
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + Duration::from_secs(interval);
        match sync(paths, &session) {
            Ok(SyncOutcome::Updated) => println!("config updated"),
            Ok(SyncOutcome::Unchanged) => {}
            Ok(SyncOutcome::SignedOut) => println!("signed out by the server; stopping"),
            Ok(SyncOutcome::Unassigned(msg)) => println!("{msg}; stopping"),
            Ok(SyncOutcome::Superseded) => println!("signed in again elsewhere in this state directory; stopping"),
            Ok(SyncOutcome::XtcpUnavailable(msg)) => {
                println!("XTCP visitor unavailable: {msg}; stopping");
                ccproxy_core::commands::touch(&paths.stop());
            }
            Err(e) => eprintln!("config check failed (keeping the current config): {e:#}"),
        }
    }
    proc.stop();
    sup.join().map_err(|_| anyhow!("supervisor panicked"))?.context("tunnel")?;
    if let Some(st) = Status::current() {
        println!("tunnel {}: {}", st.state, st.message);
    }
    Ok(())
}
