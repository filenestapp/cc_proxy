//! Start the supervisor (`ccproxy tunnel ...`) with the privileges a TUN interface needs.
//!
//!   macOS    osascript "do shell script ... with administrator privileges"  (system password prompt)
//!   Linux    pkexec                                                          (polkit prompt)
//!   Windows  ShellExecuteExW with the runas verb                             (UAC prompt)
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
        return launch_windows(cli, args);
    }
    #[allow(unreachable_code)]
    Err(anyhow!("unsupported platform"))
}

#[cfg(windows)]
fn launch_windows(cli: &Path, args: &[String]) -> Result<()> {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{ERROR_CANCELLED, RPC_E_CHANGED_MODE};
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = "runas".encode_utf16().chain([0]).collect();
    let executable: Vec<u16> = cli.as_os_str().encode_wide().chain([0]).collect();
    let command_line = args.iter().map(|arg| quote_windows_arg(arg)).collect::<Vec<_>>().join(" ");
    let parameters: Vec<u16> = command_line.encode_utf16().chain([0]).collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };

    // This runs on a blocking worker without a Windows message loop.
    let com = unsafe { CoInitializeEx(null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
    if com < 0 && com != RPC_E_CHANGED_MODE {
        anyhow::bail!("Could not initialize Windows COM (HRESULT {com:#010x})");
    }
    let error = if unsafe { ShellExecuteExW(&mut info) } == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    if com >= 0 {
        unsafe { CoUninitialize() };
    }
    match error {
        Some(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
            anyhow::bail!("Windows administrator authorization was canceled")
        }
        Some(error) => Err(error).context("Could not launch the tunnel supervisor through Windows UAC"),
        None => Ok(()),
    }
}

// Double backslashes before a literal quote or the closing quote so Windows preserves the argument.
#[cfg(any(windows, test))]
fn quote_windows_arg(arg: &str) -> String {
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        let count = if ch == '"' { backslashes * 2 + 1 } else { backslashes };
        quoted.extend(std::iter::repeat_n('\\', count));
        quoted.push(ch);
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::quote_windows_arg;

    #[test]
    fn windows_quoting_preserves_helper_paths_and_argument_boundaries() {
        assert_eq!(quote_windows_arg(""), "\"\"");
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\CC Proxy\sing-box.exe"),
            r#""C:\Program Files\CC Proxy\sing-box.exe""#
        );
        assert_eq!(quote_windows_arg(r"C:\CC Proxy\"), r#""C:\CC Proxy\\""#);
        assert_eq!(quote_windows_arg(r#"a\"b"#), r#""a\\\"b""#);
    }
}
