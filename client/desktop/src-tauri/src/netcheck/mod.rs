//! User-initiated desktop diagnostics. Only the Netcheck report fields leave this device.

mod http;
mod local;
mod packets;

use serde::Serialize;
use serde_json::Value;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SERVICE: &str = "netcheck.wenbo.io";
const TRACE_HOSTS: &[(&str, &str)] = &[
    ("anthropic", "claude.ai"),
    ("anthropic", "api.anthropic.com"),
    ("anthropic", "console.anthropic.com"),
    ("anthropic", "claude.com"),
    ("anthropic", "platform.claude.com"),
    ("openai", "chatgpt.com"),
    ("openai", "api.openai.com"),
    ("openai", "auth.openai.com"),
    ("openai", "sentinel.openai.com"),
    ("openai", "openai.com"),
    ("openai", "api.oaistatsig.com"),
    ("statsig", "featureassets.org"),
    ("hcaptcha", "js.hcaptcha.com"),
    ("cloudflare", "1.1.1.1"),
];
const IPV6_HOSTS: &[(&str, &str)] = &[
    ("anthropic", "claude.ai"),
    ("openai", "chatgpt.com"),
    ("cloudflare", "[2606:4700:4700::1111]"),
];
static RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;

impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Failure {
    Dns,
    Timeout,
    Network,
    Tls,
    NoResponse,
    Http,
    InvalidResponse,
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::Timeout,
            _ => Self::Network,
        }
    }
}

fn elapsed(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

#[derive(Default, Serialize)]
struct ExitReading {
    host: String,
    group: &'static str,
    via: &'static str,
    family: Option<u8>,
    ip: Option<IpAddr>,
    cc: Option<String>,
    colo: Option<String>,
    warp: Option<String>,
    http: Option<String>,
    tls: Option<String>,
    kex: Option<String>,
    peer: Option<IpAddr>,
    ms: Option<f64>,
    status: Option<u16>,
    error: Option<Failure>,
}

#[derive(Default, Serialize)]
struct NetworkReading {
    method: &'static str,
    server: &'static str,
    family: Option<u8>,
    ip: Option<IpAddr>,
    ecs: Option<String>,
    fake: bool,
    ms: Option<f64>,
    error: Option<Failure>,
}

#[derive(Serialize)]
struct Resolution {
    host: &'static str,
    system: Vec<IpAddr>,
    public: Vec<IpAddr>,
}

#[derive(Default, Serialize)]
struct Transport {
    connect_ms: Option<f64>,
    tls_ms: Option<f64>,
    peer: Option<IpAddr>,
    certificate_issuer: Option<String>,
    tls_version: Option<String>,
    tls_error: Option<Failure>,
    pings: Vec<f64>,
}

#[derive(Serialize)]
pub(crate) struct Report {
    local: local::Details,
    exits: Vec<ExitReading>,
    dns: Vec<NetworkReading>,
    udp: Vec<NetworkReading>,
    resolutions: Vec<Resolution>,
    transport: Transport,
    server: Option<Value>,
    server_error: Option<Failure>,
}

#[tauri::command]
pub(crate) async fn run_environment_check() -> Result<Report, &'static str> {
    if RUNNING.swap(true, Ordering::AcqRel) {
        return Err("already_running");
    }
    let guard = RunGuard;
    let job = tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        collect()
    });
    tokio::time::timeout(Duration::from_secs(45), job)
        .await
        .map_err(|_| "deadline")?
        .map_err(|_| "internal")
}

fn collect() -> Report {
    std::thread::scope(|scope| {
        let local = scope.spawn(local::collect);
        let direct = http::agent(false, None);
        let ipv6 = http::agent(true, None);
        // Keep the latency samples on the analysis connection before starting parallel probes.
        let transport = http::measure(&direct);

        let mut traces = Vec::new();
        for &(group, host) in TRACE_HOSTS {
            let agent = direct.clone();
            traces.push(scope.spawn(move || http::trace(&agent, group, host, None, "direct")));
        }
        for &(group, host) in IPV6_HOSTS {
            let agent = ipv6.clone();
            traces.push(scope.spawn(move || http::trace(&agent, group, host, Some(6), "direct")));
        }
        let dns = scope.spawn(packets::dns);
        let resolutions = scope.spawn(packets::resolutions);
        let stun = [
            scope.spawn(|| packets::stun("stun.l.google.com", 19302, 4)),
            scope.spawn(|| packets::stun("stun.cloudflare.com", 3478, 4)),
            scope.spawn(|| packets::stun("stun.l.google.com", 19302, 6)),
        ];
        let (local, proxy) = local.join().expect("local diagnostics completed");
        if let Some(proxy) = proxy {
            traces.push(scope.spawn(move || {
                let agent = http::agent(false, Some(proxy));
                http::trace(&agent, "anthropic", "claude.ai", None, "proxy")
            }));
        }
        let exits = traces
            .into_iter()
            .map(|trace| trace.join().expect("exit probe completed"))
            .collect::<Vec<_>>();
        let (dns, dns_udp) = dns.join().expect("DNS probes completed");
        let udp = stun
            .into_iter()
            .map(|probe| probe.join().expect("STUN probe completed"))
            .chain(dns_udp)
            .collect::<Vec<_>>();
        let (server, server_error) =
            match http::submit(&direct, &local, &transport, &exits, &udp, &dns) {
                Ok(server) => (Some(server), None),
                Err(error) => (None, Some(error)),
            };
        Report {
            local,
            exits,
            dns,
            udp,
            resolutions: resolutions.join().expect("DNS comparison completed"),
            transport,
            server,
            server_error,
        }
    })
}
