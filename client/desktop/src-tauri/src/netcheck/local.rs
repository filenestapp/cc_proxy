use super::packets::is_fake_ip;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use url::Url;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(4);
const OUTPUT_LIMIT: u64 = 128 * 1024;
const CLAUDE: &str = "claude.ai";

#[derive(Default, Clone, Serialize)]
struct Interface {
    name: String,
    mtu: Option<u32>,
    addresses: Vec<IpAddr>,
}

#[derive(Serialize)]
struct Route {
    interface: String,
    gateway: Option<IpAddr>,
    mtu: Option<u32>,
    tunnel: bool,
}

#[derive(Default)]
struct Platform {
    version: String,
    route: Option<Route>,
    tunnels: Vec<Interface>,
    system_proxy: BTreeMap<&'static str, String>,
    dns_servers: Vec<IpAddr>,
    vpn_services: Vec<String>,
    tailscale_exit: Option<String>,
}

#[derive(Default, Serialize)]
pub(super) struct Details {
    pub(super) os: &'static str,
    pub(super) os_version: String,
    pub(super) timezone: Option<String>,
    pub(super) utc_offset_minutes: i32,
    pub(super) languages: Vec<String>,
    architecture: &'static str,
    route: Option<Route>,
    tunnels: Vec<Interface>,
    system_proxy: BTreeMap<&'static str, String>,
    proxy_environment: Vec<String>,
    dns_servers: Vec<IpAddr>,
    vpn_services: Vec<String>,
    tailscale_exit: Option<String>,
}

pub(super) fn collect() -> (Details, Option<ureq::Proxy>) {
    let platform = platform();
    let mut dns_servers = platform.dns_servers;
    dns_servers.sort_unstable();
    dns_servers.dedup();
    let proxy_environment = ["https_proxy", "http_proxy", "all_proxy", "no_proxy"]
        .into_iter()
        .filter(|name| proxy_env(name).is_some())
        .map(str::to_owned)
        .collect();
    let actual_proxy = selected_proxy(&platform.system_proxy);
    let system_proxy = platform
        .system_proxy
        .into_iter()
        .filter_map(|(kind, value)| redact_proxy(&value).map(|address| (kind, address)))
        .collect();
    let mut languages: Vec<String> = Vec::new();
    for locale in sys_locale::get_locales() {
        let code = locale
            .split(['.', '@'])
            .next()
            .unwrap_or_default()
            .replace('_', "-");
        if code.len() >= 2
            && code.len() <= 35
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !languages.iter().any(|old| old.eq_ignore_ascii_case(&code))
        {
            languages.push(code);
        }
        if languages.len() == 6 {
            break;
        }
    }
    (
        Details {
            os: std::env::consts::OS,
            os_version: platform.version,
            timezone: iana_time_zone::get_timezone().ok(),
            utc_offset_minutes: chrono::Local::now().offset().local_minus_utc() / 60,
            languages,
            architecture: std::env::consts::ARCH,
            route: platform.route,
            tunnels: platform.tunnels,
            system_proxy,
            proxy_environment,
            dns_servers,
            vpn_services: platform.vpn_services,
            tailscale_exit: platform.tailscale_exit,
        },
        actual_proxy,
    )
}

fn proxy_env(name: &str) -> Option<String> {
    [name.to_owned(), name.to_ascii_uppercase()]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
        .find(|value| !value.trim().is_empty())
}

fn excludes(host: &str, exclusions: &str) -> bool {
    exclusions.split(',').any(|item| {
        let entry = item
            .trim()
            .trim_start_matches('.')
            .trim_end_matches(":443")
            .to_ascii_lowercase();
        entry == "*"
            || (!entry.is_empty()
                && (host == entry
                    || host
                        .strip_suffix(&entry)
                        .is_some_and(|prefix| prefix.ends_with('.'))))
    })
}

fn selected_proxy(settings: &BTreeMap<&str, String>) -> Option<ureq::Proxy> {
    if proxy_env("no_proxy").is_some_and(|list| excludes(CLAUDE, &list)) {
        return None;
    }
    ["https_proxy", "all_proxy", "http_proxy"]
        .into_iter()
        .filter_map(proxy_env)
        .chain(
            ["https", "http", "socks"]
                .into_iter()
                .filter_map(|kind| settings.get(kind).cloned()),
        )
        .find_map(|value| ureq::Proxy::new(value.trim()).ok())
}

fn proxy_address(kind: &str, value: &str) -> String {
    if value.contains("://") {
        return value.to_owned();
    }
    let scheme = if kind == "socks" { "socks5" } else { "http" };
    format!("{scheme}://{value}")
}

fn redact_proxy(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    let host = url.host()?.to_string();
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Some(format!("{}://{host}{port}", url.scheme()))
}

fn ip(value: &str) -> Option<IpAddr> {
    value.split(['%', '/']).next()?.parse().ok()
}

fn is_tunnel(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "utun",
        "tun",
        "tap",
        "wg",
        "ppp",
        "ipsec",
        "tailscale",
        "zerotier",
        "nordlynx",
        "proton",
        "mullvad",
        "clash",
        "mihomo",
        "sing-box",
        "singbox",
        "warp",
        "cloudflarewarp",
        "wintun",
        "wireguard",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn route(interface: String, gateway: Option<IpAddr>, mtu: Option<u32>) -> Route {
    let tunnel = is_tunnel(&interface) || gateway.is_some_and(is_fake_ip);
    Route {
        interface,
        gateway,
        mtu,
        tunnel,
    }
}

fn command(executable: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Option<String> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().ok()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
        std::io::Result::Ok(bytes)
    });
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    if !success {
        return None;
    }
    let bytes = reader.join().ok()?.ok()?;
    (bytes.len() as u64 <= OUTPUT_LIMIT).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

fn tailscale(executable: impl AsRef<std::ffi::OsStr>) -> Option<String> {
    let raw = command(executable, &["status", "--json"])?;
    let result: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let peers = result.get("Peer")?.as_object()?;
    peers.values().find_map(|peer| {
        if peer.get("ExitNode").and_then(serde_json::Value::as_bool) != Some(true) {
            return None;
        }
        peer.get("HostName")
            .and_then(serde_json::Value::as_str)
            .or_else(|| peer.get("DNSName").and_then(serde_json::Value::as_str))
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    })
}

#[cfg(target_os = "macos")]
fn platform() -> Platform {
    fn fields(text: &str) -> BTreeMap<&str, &str> {
        text.lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect()
    }

    let routing = command("/sbin/route", &["-n", "get", "1.1.1.1"]).unwrap_or_default();
    let routing = fields(&routing);
    let adapters = command("/sbin/ifconfig", &[]).unwrap_or_default();
    let mut interfaces = Vec::<Interface>::new();
    for line in adapters.lines() {
        if let Some((name, header)) = line.split_once(": flags=") {
            let mtu = header
                .split_once(" mtu ")
                .and_then(|(_, value)| value.split_whitespace().next()?.parse().ok());
            interfaces.push(Interface {
                name: name.to_owned(),
                mtu,
                addresses: Vec::new(),
            });
        } else if let Some((label, tail)) = line.trim().split_once(' ') {
            if matches!(label, "inet" | "inet6") {
                if let (Some(adapter), Some(address)) = (
                    interfaces.last_mut(),
                    tail.split_whitespace().next().and_then(ip),
                ) {
                    adapter.addresses.push(address);
                }
            }
        }
    }
    let route = routing.get("interface").map(|name| {
        let mtu = interfaces
            .iter()
            .find(|adapter| adapter.name == *name)
            .and_then(|adapter| adapter.mtu);
        route(
            (*name).to_owned(),
            routing.get("gateway").and_then(|value| ip(value)),
            mtu,
        )
    });
    let tunnels = interfaces
        .into_iter()
        .filter(|adapter| {
            is_tunnel(&adapter.name)
                && adapter.addresses.iter().any(|ip| match ip {
                    IpAddr::V6(ip) => !ip.is_unicast_link_local(),
                    IpAddr::V4(_) => true,
                })
        })
        .collect();

    let proxy = command("/usr/sbin/scutil", &["--proxy"]).unwrap_or_default();
    let proxy = fields(&proxy);
    let mut system_proxy = BTreeMap::new();
    for (kind, key) in [("http", "HTTP"), ("https", "HTTPS"), ("socks", "SOCKS")] {
        if proxy.get(format!("{key}Enable").as_str()) == Some(&"1") {
            if let (Some(host), Some(port)) = (
                proxy.get(format!("{key}Proxy").as_str()),
                proxy
                    .get(format!("{key}Port").as_str())
                    .and_then(|value| value.parse::<u16>().ok()),
            ) {
                system_proxy.insert(kind, proxy_address(kind, &host_port(host, port)));
            }
        }
    }
    if proxy.get("ProxyAutoConfigEnable") == Some(&"1") {
        if let Some(pac) = proxy.get("ProxyAutoConfigURLString") {
            system_proxy.insert("pac", (*pac).to_owned());
        }
    }
    let resolver = command("/usr/sbin/scutil", &["--dns"]).unwrap_or_default();
    let dns_servers = resolver
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            key.starts_with("nameserver[")
                .then(|| ip(value.trim()))
                .flatten()
        })
        .collect();
    let vpn_connections = command("/usr/sbin/scutil", &["--nc", "list"]).unwrap_or_default();
    let vpn_services = vpn_connections
        .lines()
        .filter(|line| line.contains("(Connected)"))
        .filter_map(|line| line.split('"').nth(1).map(str::to_owned))
        .collect();
    let version = command("/usr/bin/sw_vers", &["-productVersion"])
        .map(|version| format!("macOS {}", version.trim()))
        .unwrap_or_else(|| "macOS".into());
    Platform {
        version,
        route,
        tunnels,
        system_proxy,
        dns_servers,
        vpn_services,
        tailscale_exit: tailscale("/Applications/Tailscale.app/Contents/MacOS/Tailscale"),
    }
}

#[cfg(unix)]
fn host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(target_os = "linux")]
fn platform() -> Platform {
    use serde_json::Value;
    use std::fs::File;
    use std::path::Path;

    fn json_ip(args: &[&str]) -> Vec<Value> {
        let path = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip"]
            .into_iter()
            .find(|file| Path::new(file).is_file());
        path.and_then(|file| command(file, args))
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }
    fn read_settings(path: &str) -> String {
        let mut data = String::new();
        if let Ok(file) = File::open(path) {
            let _ = file.take(32 * 1024).read_to_string(&mut data);
        }
        data
    }

    let adapters = json_ip(&["-j", "address", "show"]);
    let route = json_ip(&["-j", "route", "get", "1.1.1.1"])
        .first()
        .and_then(|entry| {
            let name = entry.get("dev")?.as_str()?;
            let mtu = adapters
                .iter()
                .find(|adapter| adapter.get("ifname").and_then(Value::as_str) == Some(name))
                .and_then(|adapter| adapter.get("mtu")?.as_u64())
                .and_then(|mtu| mtu.try_into().ok());
            let gateway = entry.get("gateway").and_then(Value::as_str).and_then(ip);
            Some(route(name.to_owned(), gateway, mtu))
        });
    let tunnels = adapters
        .iter()
        .filter_map(|adapter| {
            let name = adapter.get("ifname")?.as_str()?;
            let up = adapter
                .get("flags")?
                .as_array()?
                .iter()
                .any(|flag| flag.as_str() == Some("UP"));
            if !up || !is_tunnel(name) {
                return None;
            }
            let addresses = adapter
                .get("addr_info")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|address| address.get("local")?.as_str().and_then(ip))
                .collect();
            Some(Interface {
                name: name.to_owned(),
                mtu: adapter
                    .get("mtu")
                    .and_then(Value::as_u64)
                    .and_then(|mtu| mtu.try_into().ok()),
                addresses,
            })
        })
        .collect();
    let mut system_proxy = BTreeMap::new();
    let setting = |schema: &str, key: &str| {
        command("/usr/bin/gsettings", &["get", schema, key])
            .map(|text| text.trim().trim_matches(['\'', '"']).to_owned())
    };
    match setting("org.gnome.system.proxy", "mode").as_deref() {
        Some("manual") => {
            for (kind, schema) in [
                ("http", "org.gnome.system.proxy.http"),
                ("https", "org.gnome.system.proxy.https"),
                ("socks", "org.gnome.system.proxy.socks"),
            ] {
                if let (Some(host), Some(port)) = (
                    setting(schema, "host"),
                    setting(schema, "port").and_then(|port| port.parse::<u16>().ok()),
                ) {
                    if !host.is_empty() && port != 0 {
                        system_proxy.insert(kind, proxy_address(kind, &host_port(&host, port)));
                    }
                }
            }
        }
        Some("auto") => {
            if let Some(pac) = setting("org.gnome.system.proxy", "autoconfig-url") {
                system_proxy.insert("pac", pac);
            }
        }
        _ => {}
    }
    let dns_servers = read_settings("/etc/resolv.conf")
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver")
                .then(|| words.next().and_then(ip))
                .flatten()
        })
        .collect();
    let version = read_settings("/etc/os-release")
        .lines()
        .find_map(|line| {
            line.strip_prefix("PRETTY_NAME=")
                .map(|value| value.trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| "Linux".into());
    Platform {
        version,
        route,
        tunnels,
        system_proxy,
        dns_servers,
        tailscale_exit: tailscale("/usr/bin/tailscale"),
        ..Platform::default()
    }
}

#[cfg(target_os = "windows")]
fn platform() -> Platform {
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Network {
        version: String,
        interface: Option<String>,
        gateway: Option<String>,
        mtu: Option<u32>,
        dns: Vec<String>,
        tunnels: Vec<Adapter>,
        proxy: Option<String>,
        pac: Option<String>,
    }
    #[derive(Deserialize)]
    struct Adapter {
        name: String,
        mtu: Option<u32>,
        addresses: Vec<String>,
    }

    let executable =
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let output = command(
        &executable,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("windows.ps1"),
        ],
    );
    let network: Network = output
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let route = network
        .interface
        .map(|name| route(name, network.gateway.as_deref().and_then(ip), network.mtu));
    let tunnels = network
        .tunnels
        .into_iter()
        .filter(|adapter| is_tunnel(&adapter.name))
        .map(|adapter| Interface {
            name: adapter.name,
            mtu: adapter.mtu,
            addresses: adapter
                .addresses
                .iter()
                .filter_map(|value| ip(value))
                .collect(),
        })
        .collect();
    let mut system_proxy = BTreeMap::new();
    if let Some(proxy) = network.proxy {
        for value in proxy.split(';') {
            match value.split_once('=') {
                Some(("http", endpoint)) => {
                    system_proxy.insert("http", proxy_address("http", endpoint));
                }
                Some(("https", endpoint)) => {
                    system_proxy.insert("https", proxy_address("https", endpoint));
                }
                Some(("socks", endpoint)) => {
                    system_proxy.insert("socks", proxy_address("socks", endpoint));
                }
                None => {
                    system_proxy.insert("https", proxy_address("https", value));
                }
                _ => {}
            }
        }
    }
    if let Some(pac) = network.pac {
        system_proxy.insert("pac", pac);
    }
    let version = if network.version.is_empty() {
        "Windows".into()
    } else {
        network.version
    };
    let dns_servers = network.dns.iter().filter_map(|value| ip(value)).collect();
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let tailscale_exit =
        program_files.and_then(|path| tailscale(path.join(r"Tailscale\tailscale.exe")));
    Platform {
        version,
        route,
        tunnels,
        system_proxy,
        dns_servers,
        tailscale_exit,
        ..Platform::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_proxy_labels_omit_userinfo_and_query_parameters() {
        let configured = "https://user:password@proxy.example:8443/config?token=value";
        let visible = redact_proxy(configured).unwrap();
        assert_eq!(visible, "https://proxy.example:8443");
        assert!(excludes("claude.ai", "localhost,.claude.ai"));
        assert!(!excludes("claude.ai", "otherclaude.ai"));
    }
}
