//! The privilege boundary of the tunnel supervisor (review finding CC-01).
//!
//! The supervisor runs as root / Administrator, but the sing-box config it is asked to run is written by the
//! unprivileged client into a user-writable directory. A config is code for a root process (`log.output` writes
//! anywhere, outbounds and paths can be pointed anywhere), and files in that directory can be swapped or
//! symlinked at any time. So the supervisor:
//!
//! 1. reads the user's config once per change, as a plain file of bounded size;
//! 2. extracts only the parameters a tunnel needs ([`TunnelSpec`]) and validates each one;
//! 3. renders the sing-box config itself from those parameters and requires the user's file to be exactly that
//!    rendering (any additional or different field is rejected);
//! 4. writes the rendering, with its own cache path, into a protected runtime directory owned by root /
//!    Administrators, where it also keeps its working files, log and status. `sing-box check`, the initial start,
//!    every reload and every restart use that one protected copy.
//!
//! The user directory is only ever read (the config) or stat'ed (heartbeat, stop file) by the privileged side.
//!
//! The rendering must match what the control plane's `egress/gen.py` produces for `mode=app`; the fixtures in
//! `tests/fixtures` (regenerate with `tests/fixtures/regen.py`) pin that contract.

use crate::sysdns::valid_domain;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const FAKEIP_RANGE: &str = "198.18.0.0/15";
pub const TUN_ADDRESS: &str = "172.19.0.1/30";
const FLOW: &str = "xtls-rprx-vision";
const FINGERPRINTS: &[&str] = &["chrome", "firefox", "edge", "safari", "ios", "android", "random"];
const MAX_CONFIG_BYTES: u64 = 1 << 20;
const MAX_RULE_ITEMS: usize = 500;

#[derive(Debug, Clone, PartialEq)]
pub enum DirectDns {
    Dhcp,
    Local,
    Udp(IpAddr),
}

/// Everything a client tunnel needs; nothing else crosses the privilege boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelSpec {
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
    pub domains: Vec<String>,
    pub process_names: Vec<String>,
    pub process_paths: Vec<String>,
    pub block_quic: bool,
    pub direct_dns: DirectDns,
}

// ---- protected runtime directory ------------------------------------------------------------------------

/// The supervisor's own directory. Never derived from arguments or environment the client controls.
pub fn protected_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/CCProxy")
    } else if cfg!(windows) {
        let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("CCProxy")
    } else {
        PathBuf::from("/var/lib/ccproxy")
    }
}

pub fn status_path() -> PathBuf {
    protected_dir().join("status.json")
}

/// Create (if needed) and verify the protected directory: a real directory, owned by root, writable only by its
/// owner, under a parent with the same properties (Unix). On Windows, reset its ACL to SYSTEM + Administrators
/// full control and Users read-only. `require_privileged` is false only in unit tests.
pub fn prepare_protected_dir(dir: &Path, require_privileged: bool) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", dir.display())),
    }
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("{} must be a directory, not a link", dir.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
        if require_privileged {
            for d in [Some(dir), dir.parent()].into_iter().flatten() {
                let m = fs::symlink_metadata(d)?;
                if m.uid() != 0 || m.mode() & 0o022 != 0 || m.file_type().is_symlink() {
                    bail!("{} must be owned by root and not writable by group or others", d.display());
                }
            }
        }
    }
    #[cfg(windows)]
    if require_privileged {
        let p = dir.display().to_string();
        let ok = std::process::Command::new("icacls")
            .args([&p, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
                   "*S-1-5-32-545:(OI)(CI)RX"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            bail!("could not restrict access to {p}");
        }
    }
    let _ = require_privileged;
    Ok(())
}

/// Write a file inside the protected directory (temp + rename in the same directory). `private`: 0600.
pub fn write_protected(path: &Path, data: &[u8], private: bool) -> Result<()> {
    crate::session::write_atomic(path, data, private)?;
    #[cfg(unix)]
    if !private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

// ---- reading the client's config ------------------------------------------------------------------------

/// Read the client's config: a regular file (not a link), at most 1 MiB.
pub fn read_client_config(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > MAX_CONFIG_BYTES {
        bail!("{} is larger than 1 MiB", path.display());
    }
    let mut data = Vec::new();
    fs::File::open(path)?.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut data)?;
    Ok(data)
}

/// Accept a client config: extract and validate the spec, require the file to be exactly its rendering, and return
/// the rendering with the supervisor's own cache path.
pub fn accept(client_config: &[u8], cache_path: &Path) -> Result<(TunnelSpec, Value)> {
    let value: Value = serde_json::from_slice(client_config).context("config is not JSON")?;
    let spec = extract(&value)?;
    if render(&spec, None) != value {
        bail!("config contains fields or values outside what the tunnel uses; refusing it");
    }
    let protected = render(&spec, Some(cache_path));
    Ok((spec, protected))
}

// ---- spec extraction and validation ----------------------------------------------------------------------

fn s<'a>(v: &'a Value, ptr: &str) -> Result<&'a str> {
    v.pointer(ptr).and_then(|x| x.as_str()).ok_or_else(|| anyhow!("config: {ptr} missing or not a string"))
}

fn string_list(v: Option<&Value>, what: &str) -> Result<Vec<String>> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let arr = v.as_array().ok_or_else(|| anyhow!("config: {what} is not a list"))?;
    if arr.len() > MAX_RULE_ITEMS {
        bail!("config: too many {what}");
    }
    arr.iter()
        .map(|x| x.as_str().map(String::from).ok_or_else(|| anyhow!("config: {what} entries must be strings")))
        .collect()
}

fn valid_uuid(u: &str) -> bool {
    let parts: Vec<&str> = u.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_host(h: &str) -> bool {
    h.parse::<IpAddr>().is_ok() || valid_domain(&h.to_ascii_lowercase())
}

fn valid_process_value(p: &str) -> bool {
    !p.is_empty() && p.len() <= 1024 && !p.chars().any(|c| c.is_control())
}

/// Pull the tunnel parameters out of a client config. Structure beyond these is checked by [`accept`].
pub fn extract(v: &Value) -> Result<TunnelSpec> {
    let out = v.pointer("/outbounds/0").ok_or_else(|| anyhow!("config: no egress outbound"))?;
    let server = s(out, "/server")?.to_string();
    let port = out.pointer("/server_port").and_then(|p| p.as_u64()).ok_or_else(|| anyhow!("config: server_port"))?;
    let uuid = s(out, "/uuid")?.to_string();
    let server_name = s(out, "/tls/server_name")?.to_ascii_lowercase();
    let fingerprint = s(out, "/tls/utls/fingerprint")?.to_string();
    let public_key = s(out, "/tls/reality/public_key")?.to_string();
    let short_id = s(out, "/tls/reality/short_id")?.to_string();

    if !valid_host(&server) {
        bail!("config: server {server:?} is not a host name or IP address");
    }
    if !(1..=65535).contains(&port) {
        bail!("config: server_port out of range");
    }
    if !valid_uuid(&uuid) {
        bail!("config: uuid is malformed");
    }
    if !valid_domain(&server_name) {
        bail!("config: server_name {server_name:?} is not a domain name");
    }
    if !FINGERPRINTS.contains(&fingerprint.as_str()) {
        bail!("config: unknown TLS fingerprint {fingerprint:?}");
    }
    if public_key.len() != 43 || !public_key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bail!("config: Reality public key is malformed");
    }
    if short_id.len() > 16 || short_id.len() % 2 != 0 || !short_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("config: Reality short_id is malformed");
    }

    // Rules: domains from the fake-IP DNS rule, processes and QUIC blocking from the route rules.
    let mut domains = Vec::new();
    for rule in v.pointer("/dns/rules").and_then(|r| r.as_array()).into_iter().flatten() {
        if rule.get("server").and_then(|x| x.as_str()) == Some("fakeip") {
            domains = string_list(rule.get("domain_suffix"), "domain_suffix")?;
        }
    }
    for d in &domains {
        if !valid_domain(d) {
            bail!("config: rule domain {d:?} is not a plain domain name");
        }
    }
    let mut process_names = Vec::new();
    let mut process_paths = Vec::new();
    let mut block_quic = false;
    for rule in v.pointer("/route/rules").and_then(|r| r.as_array()).into_iter().flatten() {
        if rule.get("action").and_then(|a| a.as_str()) == Some("reject") {
            block_quic = true;
        }
        if rule.get("outbound").and_then(|o| o.as_str()) == Some("egress") {
            if let Some(p) = rule.get("process_name") {
                process_names = string_list(Some(p), "process_name")?;
            }
            if let Some(p) = rule.get("process_path") {
                process_paths = string_list(Some(p), "process_path")?;
            }
        }
    }
    if !process_names.iter().chain(&process_paths).all(|p| valid_process_value(p)) {
        bail!("config: process rule values must be non-empty text without control characters");
    }

    let dns = v.pointer("/dns/servers/1").ok_or_else(|| anyhow!("config: no direct DNS server"))?;
    let direct_dns = match dns.get("type").and_then(|t| t.as_str()) {
        Some("dhcp") => DirectDns::Dhcp,
        Some("local") => DirectDns::Local,
        Some("udp") => DirectDns::Udp(
            s(dns, "/server")?.parse().map_err(|_| anyhow!("config: direct DNS server must be an IP address"))?,
        ),
        other => bail!("config: unsupported direct DNS type {other:?}"),
    };

    Ok(TunnelSpec {
        server,
        server_port: port as u16,
        uuid: uuid.to_ascii_lowercase(),
        server_name,
        fingerprint,
        public_key,
        short_id,
        domains,
        process_names,
        process_paths,
        block_quic,
        direct_dns,
    })
}

// ---- rendering (mirror of egress/gen.py build_client, mode "app") ----------------------------------------

fn with(mut base: Value, extra: Value) -> Value {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

/// The sing-box config for a spec. `cache_path` is set only for the protected copy the supervisor runs.
pub fn render(spec: &TunnelSpec, cache_path: Option<&Path>) -> Value {
    let direct_dns = match &spec.direct_dns {
        DirectDns::Dhcp => json!({"type": "dhcp", "tag": "direct-dns"}),
        DirectDns::Local => json!({"type": "local", "tag": "direct-dns"}),
        DirectDns::Udp(ip) => json!({"type": "udp", "tag": "direct-dns", "server": ip.to_string()}),
    };
    let mut dns_rules = Vec::new();
    if !spec.domains.is_empty() {
        dns_rules.push(json!({"domain_suffix": spec.domains, "query_type": ["AAAA"], "action": "predefined",
                              "rcode": "NOERROR"}));
        dns_rules.push(json!({"domain_suffix": spec.domains, "server": "fakeip"}));
    }
    let mut matchers = Vec::new();
    if !spec.domains.is_empty() {
        matchers.push(json!({"domain_suffix": spec.domains}));
    }
    matchers.push(json!({"ip_cidr": [FAKEIP_RANGE]}));
    if !spec.process_names.is_empty() {
        matchers.push(json!({"process_name": spec.process_names}));
    }
    if !spec.process_paths.is_empty() {
        matchers.push(json!({"process_path": spec.process_paths}));
    }
    let mut route_rules = vec![json!({"action": "sniff"}), json!({"protocol": "dns", "action": "hijack-dns"})];
    if spec.block_quic {
        for m in &matchers {
            route_rules.push(with(m.clone(), json!({"network": "udp", "port": 443, "action": "reject"})));
        }
    }
    for m in &matchers {
        route_rules.push(with(m.clone(), json!({"outbound": "egress"})));
    }
    let mut cache = json!({"enabled": true, "store_fakeip": true});
    if let Some(p) = cache_path {
        cache["path"] = json!(p.display().to_string());
    }
    json!({
        "log": {"level": "warn", "timestamp": true},
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": [TUN_ADDRESS], "auto_route": true, "stack": "mixed",
                      "strict_route": true}],
        "outbounds": [
            {"type": "vless", "tag": "egress", "server": spec.server, "server_port": spec.server_port,
             "uuid": spec.uuid, "flow": FLOW,
             "tls": {"enabled": true, "server_name": spec.server_name,
                     "utls": {"enabled": true, "fingerprint": spec.fingerprint},
                     "reality": {"enabled": true, "public_key": spec.public_key, "short_id": spec.short_id}}},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {"rules": route_rules, "final": "direct", "auto_detect_interface": true,
                  "default_domain_resolver": "direct-dns", "find_process": true},
        "dns": {"servers": [{"type": "fakeip", "tag": "fakeip", "inet4_range": FAKEIP_RANGE}, direct_dns],
                "rules": dns_rules, "final": "direct-dns"},
        "experimental": {"cache_file": cache}
    })
}
