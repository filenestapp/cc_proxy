//! The aifree terminal client and its internal tunnel supervisor and XTCP visitor entry points.

use anyhow::{anyhow, bail, Context, Result};
use ccproxy_core::api::Api;
use ccproxy_core::commands::{self, Connected, Effects, LoggedOut, Tunnel, HEARTBEAT_TIMEOUT_SECS};
use ccproxy_core::session::{self, Paths, Session};
use ccproxy_core::supervisor::{self, Status};
use ccproxy_core::sync::{sync_once, sync_with_visitor, SyncOutcome};
use ccproxy_core::visitor::{self, Launcher, VisitorProcess};
use ccproxy_core::{
    control_plane_url, default_device_name, elevate, platform, runtime, DEFAULT_MODE,
};
use clap::{Parser, Subcommand};
use std::cell::RefCell;
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(250);
const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);
// The other frontend may have two control-plane requests in flight before it releases the connection.
const STOP_TIMEOUT: Duration = Duration::from_secs(50);

#[derive(Parser)]
#[command(name = "aifree", version = option_env!("AIFREE_RELEASE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
          about = "aifree command-line client")]
struct Cli {
    /// Override the per-user state directory shared with the desktop app.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign in with your account email or proxy username.
    Login {
        /// Control-plane URL. Defaults to the same endpoint as the desktop app.
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        user: String,
        /// Device name shown to the administrator. Defaults to the host name.
        #[arg(long)]
        device: Option<String>,
    },
    /// Connect in the foreground. Ctrl-C or aifree disconnect stops the connection.
    Connect {
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
        #[arg(long)]
        singbox: Option<PathBuf>,
        #[arg(long)]
        frpc: Option<PathBuf>,
    },
    /// Stop the active connection, including one started by the desktop app.
    #[command(visible_alias = "down")]
    Disconnect,
    /// Show the current account, assignment, and connection state.
    Status,
    /// Sign out and revoke this device.
    Logout,
    /// Fetch configuration once for troubleshooting.
    Sync {
        #[arg(long, default_value = DEFAULT_MODE)]
        mode: String,
        #[arg(long)]
        visitor: bool,
    },
    /// Legacy foreground command. Prefer connect for automatic XTCP.
    #[command(hide = true)]
    Up {
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
        #[arg(long)]
        singbox: Option<PathBuf>,
    },
    /// Run the user-side controller with a separately started supervisor.
    #[command(hide = true)]
    Headless {
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
        #[arg(long)]
        frpc: Option<PathBuf>,
    },
    #[command(hide = true)]
    Tunnel {
        #[arg(long)]
        singbox: Option<PathBuf>,
        #[arg(long, default_value_t = HEARTBEAT_TIMEOUT_SECS)]
        heartbeat_timeout: u64,
        #[arg(long)]
        connection_id: Option<String>,
    },
    #[command(hide = true)]
    Visitor {
        #[arg(long)]
        frpc: Option<PathBuf>,
        #[arg(long)]
        route_key: Option<String>,
    },
}

fn executable() -> Result<PathBuf> {
    let path = std::env::current_exe()?;
    #[cfg(unix)]
    {
        path.canonicalize()
            .context("resolving the aifree executable")
    }
    #[cfg(windows)]
    {
        Ok(path)
    }
}

fn find_sidecar(explicit: Option<PathBuf>, base: &str) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    let name = if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    };
    if let Ok(exe) = executable() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(&name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(name)
}

fn read_password() -> Result<String> {
    if let Ok(password) =
        std::env::var("AIFREE_PASSWORD").or_else(|_| std::env::var("CCPROXY_PASSWORD"))
    {
        return Ok(password);
    }
    if io::stdin().is_terminal() {
        return rpassword::prompt_password("Password: ").context("reading the password");
    }
    let mut line = String::new();
    anyhow::ensure!(
        io::stdin().lock().read_line(&mut line)? > 0,
        "provide the password on standard input"
    );
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn options(
    paths: &Paths,
    singbox: PathBuf,
    heartbeat: Option<u64>,
    connection_id: Option<String>,
) -> supervisor::Options {
    let frpc = find_sidecar(None, "frpc");
    // An absolute result here comes from the directory containing this executable.
    // The fallback PATH lookup and any visitor command-line override are ineligible.
    let bundled_frpc = (frpc.is_absolute()
        && frpc.symlink_metadata().is_ok_and(|meta| meta.is_file()))
    .then_some(frpc);
    supervisor::Options {
        singbox,
        bundled_frpc,
        client_config: paths.config(),
        stop_file: paths.stop(),
        heartbeat: heartbeat
            .filter(|s| *s > 0)
            .map(|s| (paths.heartbeat(), Duration::from_secs(s))),
        connection_id,
        poll: Duration::from_millis(500),
        runtime_dir: runtime::protected_dir(),
        require_privileged: true,
    }
}

fn require_session(paths: &Paths) -> Result<Session> {
    Session::load(paths).ok_or_else(|| anyhow!("Sign in first with aifree login."))
}

fn login(paths: &Paths, server: Option<String>, user: &str, device: Option<String>) -> Result<()> {
    let api = Api::new(&server.unwrap_or_else(control_plane_url))?;
    let device = device
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(default_device_name);
    let user = user.trim();
    let response = api.login(user, &read_password()?, device.trim(), platform())?;
    let mut session = Session::new(
        api.base().to_owned(),
        response.user,
        response.device,
        response.token,
    );
    session.login_username = Some(user.to_owned());
    session.save(paths)?;
    println!("signed in as {user} on {}", session.device);
    Ok(())
}

fn show_status(paths: &Paths) -> Result<()> {
    if let Some(session) = Session::load(paths) {
        println!(
            "signed in as {} on {} ({})",
            session.login_username.as_deref().unwrap_or(&session.user),
            session.device,
            session.server
        );
        match Api::new(&session.server)?.me(&session.token) {
            Ok(Some(me)) => match me.entry {
                Some(entry) => println!(
                    "exit IP {} via {}:{}",
                    me.egress_ip.unwrap_or_default(),
                    entry.host,
                    entry.port
                ),
                None => println!("no exit assigned"),
            },
            Ok(None) => println!("session is no longer valid"),
            Err(error) => eprintln!("control plane unreachable: {error}"),
        }
    } else {
        println!("not signed in");
    }
    let status = Status::for_paths(paths);
    match status.as_ref() {
        Some(status) if status.running_route().is_some() => {
            let guard = visitor::guard_for_route(paths, status);
            let (state, message) = visitor::tunnel_view(paths, guard)
                .unwrap_or_else(|| (status.state.clone(), status.message.clone()));
            println!("tunnel: {state} {message}");
        }
        Some(status) => println!("tunnel: {} {}", status.state, status.message),
        None if commands::connection_requested(paths, None) => println!("tunnel: connecting"),
        None => println!("tunnel: idle"),
    }
    Ok(())
}

#[derive(Default)]
struct CliEffects {
    cli: PathBuf,
    singbox: PathBuf,
    manual: bool,
    supervisor: RefCell<Option<Child>>,
}

impl Effects for CliEffects {
    fn sync(&self, paths: &Paths, session: &Session) -> Result<SyncOutcome> {
        sync_with_visitor(paths, session, DEFAULT_MODE)
    }

    fn launch_supervisor(&self, paths: &Paths, id: &str) -> Result<()> {
        if self.manual {
            println!(
                "ready; start the privileged tunnel for state directory {}",
                paths.dir.display()
            );
            return Ok(());
        }
        let args = elevate::tunnel_args(paths, &self.singbox, HEARTBEAT_TIMEOUT_SECS, id);
        #[cfg(unix)]
        {
            let child = std::process::Command::new("sudo")
                .arg("--")
                .arg(&self.cli)
                .args(&args)
                .spawn()
                .context("starting the tunnel with sudo")?;
            self.supervisor.replace(Some(child));
            Ok(())
        }
        #[cfg(not(unix))]
        elevate::launch(&self.cli, &args)
    }

    fn remote_logout(&self, session: &Session) -> Result<()> {
        let result = Api::new(&session.server)?.logout(&session.token);
        if let Err(error) = &result {
            eprintln!("warning: server sign-out failed ({error}); forgetting the session locally");
        }
        result
    }
}

fn wait_for_stop(paths: &Paths, wait_for_controller: bool) -> Result<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    while paths.stop().exists() {
        let supervisor_running = Status::for_paths(paths).is_some_and(|status| status.is_active());
        let controller_running =
            wait_for_controller && commands::try_connection_lock(paths)?.is_none();
        if !supervisor_running && !controller_running {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "the tunnel is still stopping; check aifree status"
        );
        std::thread::sleep(POLL);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let state_dir = cli.state_dir.map(std::path::absolute).transpose()?;
    let paths = Paths::new(state_dir)?;
    match cli.cmd {
        Cmd::Login {
            server,
            user,
            device,
        } => login(&paths, server, &user, device),
        Cmd::Status => show_status(&paths),
        Cmd::Disconnect => {
            Tunnel::default().request_stop(&paths)?;
            wait_for_stop(&paths, true)?;
            println!("disconnected");
            Ok(())
        }
        Cmd::Sync { mode, visitor } => {
            let session = require_session(&paths)?;
            let outcome = if visitor {
                sync_with_visitor(&paths, &session, &mode)?
            } else {
                sync_once(&paths, &session, &mode)?
            };
            println!("{outcome:?}");
            Ok(())
        }
        Cmd::Logout => {
            let outcome = commands::logout(&paths, &Tunnel::default(), &CliEffects::default())?;
            if outcome == LoggedOut::Superseded {
                bail!("The session was replaced during sign-out.");
            }
            wait_for_stop(&paths, true)?;
            println!("signed out");
            Ok(())
        }
        Cmd::Tunnel {
            singbox,
            heartbeat_timeout,
            connection_id,
        } => {
            let connection_id = connection_id.or_else(|| {
                ccproxy_core::fsguard::read_regular_file(&paths.connection_id(), 128)
                    .ok()
                    .and_then(|data| String::from_utf8(data).ok())
            });
            supervisor::install_signal_handlers();
            supervisor::run(options(
                &paths,
                find_sidecar(singbox, "sing-box"),
                Some(heartbeat_timeout),
                connection_id,
            ))
        }
        Cmd::Visitor { frpc, route_key } => {
            let eof = Arc::new(AtomicBool::new(false));
            visitor::watch_stdin(eof.clone());
            visitor::run_guard(&paths, &find_sidecar(frpc, "frpc"), eof, route_key)
        }
        Cmd::Connect {
            interval,
            singbox,
            frpc,
        } => run_client(&paths, interval, singbox, frpc, false),
        Cmd::Headless { interval, frpc } => run_client(&paths, interval, None, frpc, true),
        Cmd::Up { interval, singbox } => legacy_up(&paths, interval, singbox),
    }
}

fn run_client(
    paths: &Paths,
    interval: u64,
    singbox: Option<PathBuf>,
    frpc: Option<PathBuf>,
    manual: bool,
) -> Result<()> {
    visitor::ensure_unprivileged().context("run aifree connect as the signed-in user")?;
    let fx = CliEffects {
        cli: executable()?,
        singbox: find_sidecar(singbox, "sing-box"),
        manual,
        supervisor: RefCell::new(None),
    };
    let launcher = Launcher {
        cli: fx.cli.clone(),
        frpc: find_sidecar(frpc, "frpc"),
    };
    let tunnel = Tunnel::default();
    supervisor::install_signal_handlers();
    if commands::connect(paths, &tunnel, &fx)? == Connected::Superseded {
        bail!("The session changed while connecting.");
    }
    let result = monitor(
        paths,
        &tunnel,
        &launcher,
        &fx,
        Duration::from_secs(interval),
    );
    let cleanup = tunnel
        .request_stop(paths)
        .and_then(|_| wait_for_stop(paths, false));
    if let Some(mut child) = fx.supervisor.into_inner() {
        // The stop request also covers a supervisor that starts after authorization completes.
        if !matches!(child.try_wait(), Ok(Some(_))) && child.kill().is_ok() {
            let _ = child.wait();
        }
    }
    result.and(cleanup)
}

fn monitor(
    paths: &Paths,
    tunnel: &Tunnel,
    launcher: &Launcher,
    fx: &CliEffects,
    interval: Duration,
) -> Result<()> {
    let started = Instant::now();
    let mut visitor = VisitorProcess::default();
    let mut shown = String::new();
    let mut was_connected = false;
    let mut next_sync = started + interval;
    let mut last_beat = started;
    loop {
        std::thread::sleep(POLL);
        if supervisor::interrupted() || paths.stop().exists() {
            return Ok(());
        }
        let status = tunnel.poll(paths);
        if let Some(status) = &status {
            match status.state.as_str() {
                "failed" => bail!("{}", status.message),
                "stopped" if supervisor::interrupted() || paths.stop().exists() => return Ok(()),
                "stopped" => bail!("the tunnel stopped: {}", status.message),
                _ => {}
            }
        }
        if !tunnel.wants_connection() {
            bail!("the connection ended before the tunnel was ready");
        }
        if let Some(child) = fx.supervisor.borrow_mut().as_mut() {
            if let Some(exit) = child.try_wait()? {
                bail!("the tunnel supervisor exited ({exit})");
            }
        }
        if last_beat.elapsed() >= HEARTBEAT_EVERY {
            commands::touch(&paths.heartbeat())?;
            last_beat = Instant::now();
        }
        visitor.ensure(paths, launcher, status.as_ref())?;
        if let Some(status) = status
            .as_ref()
            .filter(|status| status.running_route().is_some())
        {
            let (state, message) = visitor::tunnel_view(paths, visitor.guard_pid(Some(status)))
                .unwrap_or_else(|| (status.state.clone(), status.message.clone()));
            let line = format!("tunnel: {state} {message}");
            if line != shown {
                println!("{line}");
                shown = line;
            }
            was_connected |= state == "running";
            if state == "failed"
                && !was_connected
                && !visitor.is_running()
                && !visitor::read_status(paths)
                    .is_some_and(|status| status.reason == Some(visitor::Reason::ServerUnreachable))
            {
                bail!("{message}");
            }
        } else if started.elapsed() >= commands::STARTUP_TIMEOUT {
            bail!("the tunnel supervisor did not start before the timeout");
        }
        if Instant::now() >= next_sync {
            next_sync = Instant::now() + interval;
            let session = tunnel.session(paths).context("the device session ended")?;
            match sync_with_visitor(paths, &session, DEFAULT_MODE) {
                Ok(SyncOutcome::Updated) => println!("config updated"),
                Ok(SyncOutcome::Unchanged) => {}
                Ok(SyncOutcome::SignedOut) => {
                    println!("signed out by the server; stopping");
                    return Ok(());
                }
                Ok(SyncOutcome::Superseded) => return Ok(()),
                Ok(SyncOutcome::Unassigned(message) | SyncOutcome::XtcpUnavailable(message)) => {
                    bail!("{message}")
                }
                Err(error) => {
                    eprintln!("config check failed (keeping the current config): {error:#}")
                }
            }
        }
    }
}

/// Compatibility for scripts that used sudo ccproxy up for a direct or manually managed exit.
fn legacy_up(paths: &Paths, interval: u64, singbox: Option<PathBuf>) -> Result<()> {
    let _lock = commands::try_connection_lock(paths)?
        .context("a connection is already active or stopping")?;
    anyhow::ensure!(
        !Status::for_paths(paths).is_some_and(|status| status.is_active()),
        "a tunnel is still active"
    );
    let session = require_session(paths)?;
    match sync_once(paths, &session, DEFAULT_MODE)? {
        SyncOutcome::Updated | SyncOutcome::Unchanged => {}
        outcome => bail!("could not connect: {outcome:?}"),
    }
    {
        let _session = session::lock(paths)?;
        anyhow::ensure!(
            Session::is_current(paths, &session.id),
            "the session changed while connecting"
        );
        let _ = std::fs::remove_file(paths.connection_id());
        let _ = std::fs::remove_file(paths.stop());
    }
    supervisor::install_signal_handlers();
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let options = options(paths, find_sidecar(singbox, "sing-box"), None, None);
    let supervisor = std::thread::spawn(move || {
        let result = supervisor::run(options);
        finished.store(true, Ordering::SeqCst);
        result
    });
    let mut next = Instant::now() + Duration::from_secs(interval);
    while !done.load(Ordering::SeqCst) {
        std::thread::sleep(POLL);
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + Duration::from_secs(interval);
        match sync_once(paths, &session, DEFAULT_MODE) {
            Ok(SyncOutcome::Updated | SyncOutcome::Unchanged) => {}
            Ok(_) => supervisor::interrupt(),
            Err(error) => eprintln!("config check failed (keeping the current config): {error:#}"),
        }
    }
    supervisor
        .join()
        .map_err(|_| anyhow!("tunnel supervisor panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::mpsc;

    #[test]
    fn disconnect_waits_for_the_other_frontend_to_release_its_connection() {
        let paths = Paths::new(Some(std::env::temp_dir().join(session::new_session_id()))).unwrap();
        fs::write(paths.connection_id(), session::new_session_id()).unwrap();
        let lease = commands::try_connection_lock(&paths).unwrap().unwrap();
        Tunnel::default().request_stop(&paths).unwrap();

        let (send, receive) = mpsc::channel();
        let observer = paths.clone();
        let waiter = std::thread::spawn(move || send.send(wait_for_stop(&observer, true)).unwrap());
        assert!(receive.recv_timeout(Duration::from_millis(400)).is_err());
        drop(lease);
        receive
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        waiter.join().unwrap();
        fs::remove_dir_all(&paths.dir).unwrap();
    }
}
