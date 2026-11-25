use crate::{sidecar, App};
use ccproxy_core::{runtime, session::Session, supervisor::Status, visitor};
use serde::Serialize;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const IP_CHECK_URLS: [&str; 2] = ["https://v4.ident.me/", "https://api.ipify.org"];
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Serialize)]
#[serde(tag = "state", content = "ip", rename_all = "snake_case")]
pub(super) enum PublicExit {
    NotConnected,
    Checking,
    Unavailable,
    Verified(Ipv4Addr),
}

#[derive(PartialEq, Eq)]
struct Target {
    session_id: String,
    connected_at: u64,
    route: (u32, u64),
    visitor_guard: Option<u32>,
    fingerprint: String,
}

impl Target {
    fn new(app: &App, session: &Session, status: &Status) -> Option<Self> {
        let connected_at = app.tunnel.connected_at();
        if status.updated < connected_at {
            return None;
        }
        let route = status.running_route()?;
        let visitor_guard = if visitor::required(&app.paths) {
            let guard = app.visitor.lock().unwrap().guard_pid(Some(status))?;
            let (state, _) = visitor::tunnel_view(&app.paths, Some(guard))?;
            if state != "running" {
                return None;
            }
            Some(guard)
        } else {
            None
        };
        Some(Self {
            session_id: session.id.clone(),
            connected_at,
            route,
            visitor_guard,
            fingerprint: status.egress_fingerprint.clone()?,
        })
    }

    fn active(app: &App) -> Option<Self> {
        if !app.tunnel.wants_connection() {
            return None;
        }
        let session = Session::load(&app.paths)?;
        Self::new(app, &session, &Status::current()?)
    }
}

pub(super) struct Observation {
    target: Target,
    address: Option<Ipv4Addr>,
    checked_at: Instant,
}

pub(super) fn display(app: &App, session: &Session, status: &Status) -> PublicExit {
    let Some(target) = Target::new(app, session, status) else {
        return PublicExit::Unavailable;
    };
    match app
        .exit_observation
        .lock()
        .unwrap()
        .as_ref()
        .filter(|reading| reading.target == target)
    {
        Some(reading) => reading
            .address
            .map_or(PublicExit::Unavailable, PublicExit::Verified),
        None => PublicExit::Checking,
    }
}

/// Probe independently of the heartbeat and config sync so a slow HTTPS request cannot interrupt the tunnel.
pub(super) fn monitor(app: Arc<App>) {
    let binary = sidecar("sing-box");
    let config_path = app.paths.config();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let Some(target) = Target::active(&app) else {
            *app.exit_observation.lock().unwrap() = None;
            continue;
        };
        let recent = app
            .exit_observation
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|reading| {
                let retry_after = if reading.address.is_some() { 60 } else { 15 };
                reading.target == target
                    && reading.checked_at.elapsed() < Duration::from_secs(retry_after)
            });
        if !recent {
            let address = lookup(&binary, &config_path, &target.fingerprint);
            if Target::active(&app).as_ref() == Some(&target) {
                *app.exit_observation.lock().unwrap() = Some(Observation {
                    target,
                    address,
                    checked_at: Instant::now(),
                });
            }
        }
    }
}

fn lookup(binary: &Path, config_path: &Path, fingerprint: &str) -> Option<Ipv4Addr> {
    let config = runtime::read_client_config(config_path).ok()?;
    let probe = runtime::render_exit_probe(&config, fingerprint).ok()?;
    IP_CHECK_URLS
        .iter()
        .find_map(|url| fetch(binary, &probe, url))
}

fn fetch(binary: &Path, probe: &serde_json::Value, url: &str) -> Option<Ipv4Addr> {
    let mut command = Command::new(binary);
    command
        .args(["-c", "stdin", "tools", "fetch", "--outbound", "egress", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().ok()?;
    let input = child.stdin.take().expect("piped stdin");
    if serde_json::to_writer(input, probe).is_ok() {
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => {
                    let mut reply = String::new();
                    child
                        .stdout
                        .take()?
                        .take(64)
                        .read_to_string(&mut reply)
                        .ok()?;
                    return (reply.len() < 64).then(|| public_ipv4(&reply)).flatten();
                }
                Ok(Some(_)) => return None,
                Ok(None) if start.elapsed() < LOOKUP_TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => break,
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn public_ipv4(reply: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = reply.trim().parse().ok()?;
    let reserved = matches!(
        ip.octets(),
        [0 | 224..=255, ..] | [100, 64..=127, ..] | [192, 0, 0, ..] | [198, 18..=19, ..]
    );
    (!reserved
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation())
    .then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_accepts_public_ipv4_from_the_probe() {
        assert_eq!(public_ipv4("8.8.4.4\n"), Some(Ipv4Addr::new(8, 8, 4, 4)));
        for reply in [
            "192.168.1.217",
            "10.99.0.3",
            "100.64.1.2",
            "127.0.0.1",
            "169.254.1.2",
            "198.18.0.1",
            "203.0.113.9",
            "255.255.255.255",
            "::1",
            "8.8.4.4:443",
            "<html>",
        ] {
            assert_eq!(public_ipv4(reply), None, "{reply}");
        }
    }
}
