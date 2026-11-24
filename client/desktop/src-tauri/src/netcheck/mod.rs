//! User-initiated desktop diagnostics. Only the Netcheck report fields leave this device.

mod http;
mod local;
mod packets;

use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinError, JoinSet};
use tokio::time::{timeout_at, Instant as Deadline};

const SERVICE: &str = "netcheck.wenbo.io";
const CHECK_TIMEOUT: Duration = Duration::from_secs(45);
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
const STUN_TARGETS: &[(&str, u16, u8)] = &[
    ("stun.l.google.com", 19302, 4),
    ("stun.cloudflare.com", 3478, 4),
    ("stun.l.google.com", 19302, 6),
];
const PROXY_EXIT: usize = TRACE_HOSTS.len() + IPV6_HOSTS.len();

static RUNNING: AsyncMutex<()> = AsyncMutex::const_new(());
static PROBES: LazyLock<ProbeSlots> = LazyLock::new(ProbeSlots::default);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Probe {
    Local,
    Transport,
    Exit(usize),
    Dns,
    Stun(usize),
    Resolutions,
    Analysis,
}

#[derive(Default)]
struct ProbeSlots(Mutex<HashSet<Probe>>);

struct ProbeGuard {
    slots: &'static ProbeSlots,
    probe: Probe,
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        self.slots.0.lock().unwrap().remove(&self.probe);
    }
}

impl ProbeSlots {
    fn spawn<T: Send + 'static>(
        &'static self,
        jobs: &mut JoinSet<T>,
        probe: Probe,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> bool {
        // The OS resolver can outlive our deadline. Keep one worker per probe until it actually exits.
        if !self.0.lock().unwrap().insert(probe) {
            return false;
        }
        let permit = ProbeGuard { slots: self, probe };
        jobs.spawn_blocking(move || {
            let _permit = permit;
            work()
        });
        true
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

#[derive(Default, Serialize)]
pub(crate) struct Report {
    local: local::Details,
    exits: Vec<ExitReading>,
    dns: Vec<NetworkReading>,
    udp: Vec<NetworkReading>,
    resolutions: Vec<Resolution>,
    transport: Transport,
    server: Option<Value>,
    server_error: Option<Failure>,
    incomplete: bool,
}

enum ResultPart {
    Local(local::Details, Option<ureq::Proxy>),
    Transport(Transport),
    Exit(usize, ExitReading),
    Dns(Vec<NetworkReading>, Vec<NetworkReading>),
    Stun(usize, NetworkReading),
}

#[tauri::command]
pub(crate) async fn run_environment_check() -> Result<Report, &'static str> {
    run_check(&RUNNING, collect(&PROBES)).await
}

async fn run_check(
    running: &AsyncMutex<()>,
    check: impl Future<Output = Report>,
) -> Result<Report, &'static str> {
    let _run = running.try_lock().map_err(|_| "already_running")?;
    Ok(check.await)
}

async fn next_before<T: 'static>(
    jobs: &mut JoinSet<T>,
    deadline: Deadline,
) -> Option<Result<T, JoinError>> {
    timeout_at(deadline, jobs.join_next()).await.ok().flatten()
}

async fn collect(slots: &'static ProbeSlots) -> Report {
    let deadline = Deadline::now() + CHECK_TIMEOUT;
    let direct = http::agent(false, None);
    let ipv6 = http::agent(true, None);
    let analysis_client = http::agent(false, None);

    let mut jobs = JoinSet::new();
    let mut incomplete = !slots.spawn(&mut jobs, Probe::Local, || {
        let (details, proxy) = local::collect();
        ResultPart::Local(details, proxy)
    });
    let measurement_client = analysis_client.clone();
    incomplete |= !slots.spawn(&mut jobs, Probe::Transport, move || {
        ResultPart::Transport(http::measure(&measurement_client))
    });

    let traces = TRACE_HOSTS
        .iter()
        .map(|&(group, host)| (group, host, None, &direct))
        .chain(
            IPV6_HOSTS
                .iter()
                .map(|&(group, host)| (group, host, Some(6), &ipv6)),
        );
    for (index, (group, host, family, agent)) in traces.enumerate() {
        let agent = agent.clone();
        incomplete |= !slots.spawn(&mut jobs, Probe::Exit(index), move || {
            ResultPart::Exit(index, http::trace(&agent, group, host, family, "direct"))
        });
    }
    incomplete |= !slots.spawn(&mut jobs, Probe::Dns, || {
        let (dns, udp) = packets::dns();
        ResultPart::Dns(dns, udp)
    });
    for (index, &(host, port, family)) in STUN_TARGETS.iter().enumerate() {
        incomplete |= !slots.spawn(&mut jobs, Probe::Stun(index), move || {
            ResultPart::Stun(index, packets::stun(host, port, family))
        });
    }
    let mut resolutions = JoinSet::new();
    slots.spawn(&mut resolutions, Probe::Resolutions, packets::resolutions);

    let mut report = read_probes(slots, jobs, deadline, incomplete).await;

    // DNS comparison is independent of the service report, which can start while it finishes.
    let mut analysis = JoinSet::new();
    if Deadline::now() < deadline {
        let payload = http::payload(
            &report.local,
            &report.transport,
            &report.exits,
            &report.udp,
            &report.dns,
        );
        slots.spawn(&mut analysis, Probe::Analysis, move || {
            http::submit(
                &analysis_client,
                payload,
                deadline.saturating_duration_since(Deadline::now()),
            )
        });
    }

    match next_before(&mut resolutions, deadline).await {
        Some(Ok(results)) => report.resolutions = results,
        _ => report.incomplete = true,
    }
    match next_before(&mut analysis, deadline).await {
        Some(Ok(Ok(result))) => report.server = Some(result),
        Some(Ok(Err(error))) => report.server_error = Some(error),
        Some(Err(_)) => report.server_error = Some(Failure::Network),
        None => report.server_error = Some(Failure::Timeout),
    }
    report
}

async fn read_probes(
    slots: &'static ProbeSlots,
    mut jobs: JoinSet<ResultPart>,
    deadline: Deadline,
    incomplete: bool,
) -> Report {
    let mut report = Report {
        incomplete,
        ..Report::default()
    };
    let mut exits = Vec::new();
    let mut stun = Vec::new();
    let mut dns_udp = Vec::new();
    while !jobs.is_empty() {
        let part = match next_before(&mut jobs, deadline).await {
            Some(Ok(part)) => part,
            Some(Err(_)) => {
                report.incomplete = true;
                continue;
            }
            None => {
                report.incomplete = true;
                break;
            }
        };
        match part {
            ResultPart::Local(details, proxy) => {
                report.local = details;
                if let Some(proxy) = proxy {
                    report.incomplete |= Deadline::now() >= deadline
                        || !slots.spawn(&mut jobs, Probe::Exit(PROXY_EXIT), move || {
                            let agent = http::agent(false, Some(proxy));
                            let result =
                                http::trace(&agent, "anthropic", "claude.ai", None, "proxy");
                            ResultPart::Exit(PROXY_EXIT, result)
                        });
                }
            }
            ResultPart::Transport(transport) => report.transport = transport,
            ResultPart::Exit(index, result) => exits.push((index, result)),
            ResultPart::Dns(dns, udp) => {
                report.dns = dns;
                dns_udp = udp;
            }
            ResultPart::Stun(index, result) => stun.push((index, result)),
        }
    }
    exits.sort_by_key(|(index, _)| *index);
    stun.sort_by_key(|(index, _)| *index);
    report.exits = exits.into_iter().map(|(_, row)| row).collect();
    report.udp = stun
        .into_iter()
        .map(|(_, row)| row)
        .chain(dns_udp)
        .collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn exit(last_octet: u8) -> ResultPart {
        ResultPart::Exit(
            0,
            ExitReading {
                host: "example.test".to_owned(),
                ip: Some([203, 0, 113, last_octet].into()),
                ..ExitReading::default()
            },
        )
    }

    fn dns(last_octet: u8) -> ResultPart {
        let reading = NetworkReading {
            server: "resolver.test",
            ip: Some([203, 0, 113, last_octet].into()),
            ..NetworkReading::default()
        };
        ResultPart::Dns(vec![reading], Vec::new())
    }

    #[test]
    fn deadline_returns_completed_probes_and_retry_runs_while_dns_is_stalled() {
        static SLOTS: LazyLock<ProbeSlots> = LazyLock::new(ProbeSlots::default);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let running = AsyncMutex::new(());
            let (release_dns, wait_for_dns) = mpsc::channel();
            let (dns_started, wait_for_start) = mpsc::sync_channel(1);
            let mut first = JoinSet::new();
            assert!(SLOTS.spawn(&mut first, Probe::Dns, move || {
                dns_started.send(()).unwrap();
                let _ = wait_for_dns.recv();
                dns(6)
            }));
            assert!(SLOTS.spawn(&mut first, Probe::Exit(0), || exit(7)));
            wait_for_start.recv_timeout(Duration::from_secs(2)).unwrap();

            let report = run_check(
                &running,
                read_probes(
                    &SLOTS,
                    first,
                    Deadline::now() + Duration::from_millis(200),
                    false,
                ),
            )
            .await
            .unwrap();
            assert!(report.incomplete);
            assert_eq!(report.exits.len(), 1);
            assert_eq!(report.exits[0].ip, Some([203, 0, 113, 7].into()));

            let mut retry = JoinSet::new();
            assert!(!SLOTS.spawn(&mut retry, Probe::Dns, || panic!("duplicate DNS worker")));
            assert!(SLOTS.spawn(&mut retry, Probe::Exit(0), || exit(8)));
            let report = run_check(
                &running,
                read_probes(
                    &SLOTS,
                    retry,
                    Deadline::now() + Duration::from_secs(2),
                    true,
                ),
            )
            .await
            .unwrap();
            assert!(report.incomplete);
            assert_eq!(report.exits.len(), 1);
            assert_eq!(report.exits[0].ip, Some([203, 0, 113, 8].into()));
            assert!(report.dns.is_empty());

            release_dns.send(()).unwrap();
            let mut later = JoinSet::new();
            let recovery_deadline = Deadline::now() + Duration::from_secs(2);
            while !SLOTS.spawn(&mut later, Probe::Dns, || dns(9)) {
                assert!(Deadline::now() < recovery_deadline);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let report = run_check(
                &running,
                read_probes(&SLOTS, later, recovery_deadline, false),
            )
            .await
            .unwrap();
            assert!(!report.incomplete);
            assert_eq!(report.dns[0].ip, Some([203, 0, 113, 9].into()));
        });
    }

    #[test]
    fn simultaneous_checks_are_still_rejected() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let running = AsyncMutex::new(());
            let _active = running.lock().await;
            let second = run_check(&running, std::future::ready(Report::default())).await;
            assert_eq!(second.err(), Some("already_running"));
        });
    }
}
