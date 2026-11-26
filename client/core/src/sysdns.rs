//! Make the OS resolver send rule domains to the TUN's DNS, and drop cached answers when the tunnel changes.
//!
//! Why: on macOS the system resolver (mDNSResponder) sends queries bound to the physical interface, so they never
//! enter the TUN and its DNS hijack never sees them; rule domains then resolve to real addresses (or NXDOMAIN for
//! names that only exist behind the exit). Per-domain resolver files (`/etc/resolver/<domain>`) pointing at the
//! TUN's DNS address fix that for exactly the rule domains and leave every other lookup alone.
//!
//! Every OS also caches answers across connect / disconnect / rule changes, so we flush after each.
//!
//! Domains come from the config the control plane serves and these files are written as root, so names are
//! validated strictly; anything that is not a plain DNS name is skipped.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// DNS address inside the TUN subnet (egress/gen.py: TUN_ADDRESS 172.19.0.1/30, TUN_DNS 172.19.0.2).
pub const TUN_DNS: &str = "172.19.0.2";
const MARK: &str = "# managed by ccproxy";

/// DNS names that need a scoped resolver for the client config's fake-IP rules.
pub fn rule_domains(config: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let rules = config.pointer("/dns/rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    for rule in rules {
        if rule.get("server").and_then(|s| s.as_str()) != Some("fakeip") {
            continue;
        }
        for kind in ["domain_suffix", "domain"] {
            for d in rule.get(kind).and_then(|d| d.as_array()).into_iter().flatten() {
                if let Some(name) = d.as_str().map(|s| s.trim_start_matches('.').to_ascii_lowercase()) {
                    if valid_domain(&name) && !out.contains(&name) {
                        out.push(name);
                    }
                }
            }
        }
    }
    out
}

/// A plain DNS name: labels of [a-z0-9-], not starting or ending with '-', at least two labels.
pub fn valid_domain(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Write `<dir>/<domain>` for each domain, remove our files for domains no longer listed. Files we did not
/// write are never touched. Returns the domains now routed to the TUN.
pub fn apply_resolver_files(dir: &Path, domains: &[String]) -> std::io::Result<Vec<String>> {
    fs::create_dir_all(dir)?;
    let body = format!("{MARK}\nnameserver {TUN_DNS}\n");
    remove_resolver_files(dir, domains)?;
    let mut applied = Vec::new();
    for d in domains {
        if !valid_domain(d) {
            continue;
        }
        let path = dir.join(d);
        match fs::read_to_string(&path) {
            Ok(existing) if !existing.starts_with(MARK) => continue, // someone else's file: leave it
            _ => {}
        }
        fs::write(&path, &body)?;
        applied.push(d.clone());
    }
    Ok(applied)
}

/// Remove the files we wrote, except those for `keep`.
pub fn remove_resolver_files(dir: &Path, keep: &[String]) -> std::io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if keep.contains(&name) {
            continue;
        }
        if fs::read_to_string(entry.path()).map(|s| s.starts_with(MARK)).unwrap_or(false) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn resolver_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        Some(PathBuf::from("/etc/resolver"))
    } else {
        None
    }
}

fn run_quiet(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

/// Drop the OS resolver's cached answers.
pub fn flush_cache() {
    if cfg!(target_os = "macos") {
        run_quiet("dscacheutil", &["-flushcache"]);
        run_quiet("killall", &["-HUP", "mDNSResponder"]);
    } else if cfg!(target_os = "windows") {
        run_quiet("ipconfig", &["/flushdns"]);
    } else {
        run_quiet("resolvectl", &["flush-caches"]);
    }
}

/// Point the OS at the TUN's DNS for the rule domains of `config` (macOS), then flush. Returns the domains.
pub fn apply(config: &Path) -> Vec<String> {
    let domains = fs::read(config)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .map(|c| rule_domains(&c))
        .unwrap_or_default();
    let applied = match resolver_dir() {
        Some(dir) => apply_resolver_files(&dir, &domains).unwrap_or_default(),
        None => domains,
    };
    flush_cache();
    applied
}

/// Undo [`apply`] and flush, so cached fake IPs do not outlive the tunnel.
pub fn restore() {
    if let Some(dir) = resolver_dir() {
        let _ = remove_resolver_files(&dir, &[]);
    }
    flush_cache();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_validation() {
        for ok in ["example.com", "echo.example.com", "a-b.example.co", "x1.y2"] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in ["", "com", "../etc/sudoers", "a/b.com", "a..com", "-a.com", "a-.com", "A.com", "a b.com",
                    ".example.com", "example.com.", "x".repeat(64).as_str()] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn rule_domains_come_from_fakeip_rules_only_and_unsafe_names_are_dropped() {
        let cfg = serde_json::json!({"dns": {"rules": [
            {"domain_suffix": ["echo.example.com"], "query_type": ["AAAA"], "action": "predefined"},
            {"domain_suffix": ["echo.example.com", ".Other.example.org", "../../etc/passwd", "localhost"], "server": "fakeip"},
            {"domain": ["echo.example.com", "Gemini.example.net"], "server": "fakeip"},
            {"domain_suffix": ["direct.example.net"], "server": "direct-dns"}
        ]}});
        assert_eq!(rule_domains(&cfg), vec!["echo.example.com", "other.example.org", "gemini.example.net"]);
    }

    #[test]
    fn resolver_files_are_written_replaced_and_removed_without_touching_foreign_files() {
        let dir = std::env::temp_dir().join(format!("ccproxy-sysdns-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("corp.example.com"), "nameserver 10.0.0.53\n").unwrap(); // not ours

        let first = apply_resolver_files(&dir, &["a.example.com".into(), "corp.example.com".into()]).unwrap();
        assert_eq!(first, vec!["a.example.com"]);
        assert!(fs::read_to_string(dir.join("a.example.com")).unwrap().contains("nameserver 172.19.0.2"));
        assert_eq!(fs::read_to_string(dir.join("corp.example.com")).unwrap(), "nameserver 10.0.0.53\n");

        apply_resolver_files(&dir, &["b.example.com".into()]).unwrap();
        assert!(!dir.join("a.example.com").exists());
        assert!(dir.join("b.example.com").exists());

        remove_resolver_files(&dir, &[]).unwrap();
        assert!(!dir.join("b.example.com").exists());
        assert!(dir.join("corp.example.com").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
