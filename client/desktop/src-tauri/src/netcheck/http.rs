use super::{elapsed, local::Details, ExitReading, Failure, NetworkReading, Transport, SERVICE};
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use x509_cert::{der::Decode, Certificate};

const USER_AGENT: &str = concat!(
    "CC-Proxy/",
    env!("CARGO_PKG_VERSION"),
    " (environment-check)"
);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(4);
const PING_BUDGET: Duration = Duration::from_secs(4);
const PINGS: usize = 20;
const ORIGIN: &str = "https://netcheck.wenbo.io";

static TLS: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("supported TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
});

pub(super) fn agent(ipv6: bool, proxy: Option<ureq::Proxy>) -> ureq::Agent {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(IO_TIMEOUT)
        .timeout_write(IO_TIMEOUT)
        .timeout(Duration::from_secs(6))
        .redirects(0)
        .user_agent(USER_AGENT)
        .try_proxy_from_env(false)
        .tls_config(TLS.clone());
    if ipv6 {
        builder = builder.resolver(|host: &str| {
            let addrs: Vec<_> = host
                .to_socket_addrs()?
                .filter(|addr| addr.is_ipv6())
                .collect();
            if addrs.is_empty() {
                Err(io::Error::new(io::ErrorKind::NotFound, "no IPv6 address"))
            } else {
                Ok(addrs)
            }
        });
    }
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy);
    }
    builder.build()
}

fn transport_error(error: ureq::Error) -> Failure {
    match error {
        ureq::Error::Status(_, _) => Failure::Http,
        ureq::Error::Transport(error) if error.kind() == ureq::ErrorKind::Dns => Failure::Dns,
        ureq::Error::Transport(error) => {
            // The transport does not expose a dedicated TLS or timeout error kind.
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("timed out") || message.contains("timeout") {
                Failure::Timeout
            } else if message.contains("tls") || message.contains("certificate") {
                Failure::Tls
            } else {
                Failure::Network
            }
        }
    }
}

fn read_body(response: ureq::Response, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut body = Vec::new();
    response
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut body)?;
    if body.len() > limit {
        return Err(Failure::InvalidResponse);
    }
    Ok(body)
}

fn trace_fields(body: &[u8]) -> Result<HashMap<&str, &str>, Failure> {
    let text = std::str::from_utf8(body).map_err(|_| Failure::InvalidResponse)?;
    Ok(text
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(_, value)| value.len() <= 128)
        .collect())
}

pub(super) fn trace(
    agent: &ureq::Agent,
    group: &'static str,
    host: &'static str,
    family: Option<u8>,
    via: &'static str,
) -> ExitReading {
    let start = Instant::now();
    let mut result = ExitReading {
        host: host.trim_matches(['[', ']']).to_owned(),
        group,
        via,
        family,
        ..ExitReading::default()
    };
    let reply = agent
        .get(&format!("https://{host}/cdn-cgi/trace"))
        .set("Cache-Control", "no-cache")
        .call();
    let response = match reply {
        Ok(response) => response,
        Err(error) => {
            if let ureq::Error::Status(status, _) = &error {
                result.status = Some(*status);
            }
            result.error = Some(transport_error(error));
            return result;
        }
    };
    result.status = Some(response.status());
    if response.status() != 200 {
        result.error = Some(Failure::Http);
        return result;
    }
    if via == "direct" {
        result.peer = Some(response.remote_addr().ip());
    }
    let parsed = (|| -> Result<(), Failure> {
        let body = read_body(response, 32 * 1024)?;
        let fields = trace_fields(&body)?;
        result.ip = Some(
            fields
                .get("ip")
                .and_then(|ip| ip.parse().ok())
                .ok_or(Failure::NoResponse)?,
        );
        result.cc = fields
            .get("loc")
            .filter(|v| v.len() == 2)
            .map(|v| v.to_string());
        result.colo = fields.get("colo").map(|v| v.to_string());
        result.warp = fields.get("warp").map(|v| v.to_string());
        result.http = fields.get("http").map(|v| v.to_string());
        result.tls = fields.get("tls").map(|v| v.to_string());
        result.kex = fields.get("kex").map(|v| v.to_string());
        Ok(())
    })();
    result.error = parsed.err();
    result.ms = Some(elapsed(start));
    result
}

pub(super) fn measure(agent: &ureq::Agent) -> Transport {
    let mut result = Transport::default();
    result.tls_error = measure_tls(&mut result).err();

    let started = Instant::now();
    for sample in 0..PINGS {
        let Some(remaining) = PING_BUDGET.checked_sub(started.elapsed()) else {
            break;
        };
        let start = Instant::now();
        let request = agent
            .get(&format!("{ORIGIN}/api/cli/ping?i={sample}"))
            .timeout(remaining);
        let reply = request
            .call()
            .map_err(transport_error)
            .and_then(|response| {
                if response.status() != 200 {
                    return Err(Failure::Http);
                }
                read_body(response, 4096)
            });
        if reply.is_err() {
            break;
        }
        result.pings.push(elapsed(start));
    }
    result
}

fn measure_tls(result: &mut Transport) -> Result<(), Failure> {
    let addrs = (SERVICE, 443).to_socket_addrs().map_err(|_| Failure::Dns)?;
    let start = Instant::now();
    let mut failure = Failure::Dns;
    let mut stream = addrs
        .take(2)
        .find_map(
            |addr| match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(stream) => Some(stream),
                Err(error) => {
                    failure = error.into();
                    None
                }
            },
        )
        .ok_or(failure)?;
    result.connect_ms = Some(elapsed(start));
    result.peer = stream.peer_addr().ok().map(|peer| peer.ip());
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let name = ServerName::try_from(SERVICE).expect("valid diagnostics hostname");
    let mut connection =
        rustls::ClientConnection::new(TLS.clone(), name).map_err(|_| Failure::Tls)?;
    let start = Instant::now();
    while connection.is_handshaking() {
        if let Err(error) = connection.complete_io(&mut stream) {
            return Err(match Failure::from(error) {
                Failure::Timeout => Failure::Timeout,
                _ => Failure::Tls,
            });
        }
    }
    result.tls_ms = Some(elapsed(start));
    result.tls_version = connection
        .protocol_version()
        .map(|version| format!("{version:?}"));
    result.certificate_issuer = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|der| Certificate::from_der(der.as_ref()).ok())
        .map(|cert| cert.tbs_certificate.issuer.to_string());
    Ok(())
}

pub(super) fn submit(
    agent: &ureq::Agent,
    local: &Details,
    transport: &Transport,
    exits: &[ExitReading],
    udp: &[NetworkReading],
    dns: &[NetworkReading],
) -> Result<Value, Failure> {
    let payload = payload(local, transport, exits, udp, dns);
    let response = agent
        .post(&format!("{ORIGIN}/api/cli/report"))
        .timeout(Duration::from_secs(12))
        .send_json(payload)
        .map_err(transport_error)?;
    if response.status() != 200 {
        return Err(Failure::Http);
    }
    let report: Value = serde_json::from_slice(&read_body(response, 512 * 1024)?)
        .map_err(|_| Failure::InvalidResponse)?;
    if !report.get("signals").is_some_and(Value::is_array) {
        return Err(Failure::InvalidResponse);
    }
    Ok(report)
}

fn payload(
    local: &Details,
    transport: &Transport,
    exits: &[ExitReading],
    udp: &[NetworkReading],
    dns: &[NetworkReading],
) -> Value {
    // This is an explicit allowlist, independent of the much larger report exposed to the local UI.
    let exits: Vec<_> = exits.iter().map(|row| json!({
        "host": row.host, "group": row.group, "family": row.family, "via": row.via,
        "ip": row.ip, "cc": row.cc, "colo": row.colo, "warp": row.warp, "ms": row.ms, "error": row.error,
    })).collect();
    json!({
        "v": "1",
        "os": local.os,
        "os_version": local.os_version,
        "tz": local.timezone,
        "tz_offset_min": local.utc_offset_minutes,
        "langs": local.languages,
        "pings": transport.pings,
        "connect_ms": transport.connect_ms,
        "tls_ms": transport.tls_ms,
        "exits": exits,
        "udp": udp,
        "dns": dns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_requests_exclude_local_endpoints_and_certificates() {
        let ip = "203.0.113.42".parse().unwrap();
        let local_address = "192.168.1.1".parse().unwrap();
        let local = Details::default();
        let transport = Transport {
            peer: Some(local_address),
            certificate_issuer: Some("Local issuer".into()),
            ..Transport::default()
        };
        let exit = ExitReading {
            ip: Some(ip),
            peer: Some(local_address),
            ..ExitReading::default()
        };
        let request = payload(&local, &transport, &[exit], &[], &[]);
        assert_eq!(request["exits"][0]["ip"], "203.0.113.42");
        assert!(request["exits"][0].get("peer").is_none());
        assert!(request.get("local").is_none());
        assert!(request.get("system_proxy").is_none());
        let wire = request.to_string();
        assert!(!wire.contains("192.168.1.1"));
        assert!(!wire.contains("Local issuer"));
    }
}
