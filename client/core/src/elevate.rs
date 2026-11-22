//! Start the supervisor (`ccproxy tunnel ...`) with the privileges a TUN interface needs.
//!
//!   macOS    osascript "do shell script ... with administrator privileges"  (system password prompt)
//!   Linux    pkexec                                                          (polkit prompt)
//!   Windows  PowerShell Start-Process -Verb RunAs                            (UAC prompt)
//!
//! One prompt per connect. Stopping needs no privileges: the app writes the stop file, and the supervisor also
//! stops by itself when the app's heartbeat goes stale, so a crashed app never leaves a root sing-box behind.

use crate::session::Paths;
use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

/// Arguments for `ccproxy tunnel` that point the supervisor at the shared files in `paths`.
pub fn tunnel_args(paths: &Paths, singbox: &Path, heartbeat_timeout_secs: u64) -> Vec<String> {
    vec![
        "--state-dir".into(),
        paths.dir.display().to_string(),
        "tunnel".into(),
        "--singbox".into(),
        singbox.display().to_string(),
        "--heartbeat-timeout".into(),
        heartbeat_timeout_secs.to_string(),
    ]
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// POSIX shell single-quote escaping.
#[allow(dead_code)]
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Launch `cli args...` elevated and detached. Returns once the launch was accepted (or refused).
/// Output goes nowhere: the supervisor logs into its protected runtime directory, never into a user-writable file.
pub fn launch(cli: &Path, args: &[String]) -> Result<()> {
    if is_root() {
        Command::new(cli).args(args).spawn().context("starting tunnel")?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let mut cmd = sh_quote(&cli.display().to_string());
        for a in args {
            cmd.push(' ');
            cmd.push_str(&sh_quote(a));
        }
        cmd.push_str(" >/dev/null 2>&1 &");
        // AppleScript string literal: escape backslashes and double quotes.
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let out = Command::new("osascript").args(["-e", &script]).output().context("running osascript")?;
        if !out.status.success() {
            return Err(anyhow!("authorisation refused or failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("pkexec").arg(cli).args(args).spawn().context("running pkexec (is polkit installed?)")?;
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let arglist = args.iter().map(|a| quote(&format!("\"{a}\""))).collect::<Vec<_>>().join(",");
        let ps = format!(
            "Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden",
            quote(&cli.display().to_string()),
            if arglist.is_empty() { "@()".into() } else { arglist }
        );
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .context("running PowerShell")?;
        if !out.status.success() {
            return Err(anyhow!("authorisation refused or failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err(anyhow!("unsupported platform"))
}
