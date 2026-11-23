# Exit-node installer and Go agent

An exit host is added in the control-plane console and installed with one copied command. The node runs two
programs, both downloaded and checked by the installer:

| Program | Source | Integrity |
| --- | --- | --- |
| `ccproxy-exit-agent` | [`egress/agent`](../agent) (Go, standard library only), served by the control plane | SHA-256 from the reproducible build's `SHA256SUMS`, embedded in the served install script |
| `sing-box` 1.14.4 | Official GitHub release | SHA-256 pinned in [`sing-box.json`](sing-box.json) (same version as `client/desktop/scripts/fetch-binaries.sh`) |

The node needs no Go, Python or repository checkout. macOS and Linux need `curl` (and systemd on Linux); Windows
needs nothing beyond Windows PowerShell 5.1. The Python agent ([`controlplane/agent.py`](../../controlplane/agent.py))
is unchanged and stays available to existing deployments and the Docker end-to-end tests.

## Build and publish the agent

```bash
egress/agent/build.sh --verify          # builds 6 targets twice and fails unless the results are identical
```

Output: `egress/agent/dist/ccproxy-exit-agent-{darwin,linux}-{arm64,amd64}`, `...-windows-{amd64,arm64}.exe`,
`SHA256SUMS` and `VERSION`. The build pins the Go toolchain (`go.mod`), disables cgo, and uses `-trimpath`, no VCS
stamp and an empty build ID, so the same commit and version give byte-identical files. The control plane serves
the directory set by `CP_AGENT_DIST` (default `egress/agent/dist`). It hashes each binary against `SHA256SUMS`
before embedding digests in a script or serving a file. If a binary is missing or changed, `/install/*` answers 503
and names `build.sh`. CI (`.github/workflows/exit-agent.yml`) runs the Go tests and the reproducibility check, then
uploads `dist` as an artifact. Deploy that directory next to the control plane.

| Route | Access |
| --- | --- |
| `GET /install/exit.sh`, `/install/exit.ps1`, `/install/manifest.json` | Public. Contains only code and digests |
| `GET /install/agent/{os}-{arch}` | Host agent token required. The token is checked like any agent call |
| `GET /admin/install-commands?cp=URL[&iface=IF]` | Admin. Returns the copy-ready commands for macOS, Linux and Windows |

## Console flow

**Egress hosts → Add host** shows the agent token once, with an OS selector (macOS, Linux, Windows) and copyable
install and uninstall commands. **Rotate agent token** shows the same dialog for the new token. **Install command**
on a host page shows the commands without a token. The token is never part of a command. The installer asks for it
with hidden input. Switching OS or editing the URL clears the commands and disables **Copy** until the matching
commands arrive.

The commands are generated only for an `https://` control-plane URL. Every field is checked against a full-string
pattern before it is put into a command.

```sh
(f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
  'https://cp.example:8443/install/exit.sh' -o "$f" && sudo sh "$f" --cp 'https://cp.example:8443'; \
  s=$?; rm -f "$f"; exit $s)
```

The script is fully downloaded before `sudo` runs, and a failed download never reaches it. `curl -q` ignores any
`.curlrc`, and `--proto =https` applies to redirects too. The subshell removes the temporary file and exits with the
status of `curl` or the installer, so a failure is reported as one. The Windows command fetches the script without
following redirects. It runs the script only when the download is a string that starts with the installer's first
line.

## What the installer guarantees

- **Token handling.** The token is read without echo, or with `--token-file` / `-TokenFile`. It is validated against
  `/agent/probe-targets` before anything changes. It is stored in `/etc/ccproxy-exit/agent.token` (root, 0600), or
  on Windows in `C:\ProgramData\CCProxyExit\agent.token` (SYSTEM and Administrators only). It never appears in an
  argument list: curl reads it from a config on stdin, and the agent reads it with `--token-file`. Requests that
  carry the token never follow a redirect, in the installer or in the agent.
- **Trusted paths.** A root or SYSTEM service runs only files that normal users cannot change. On macOS and Linux,
  every path component up to `/` must be root-owned and not writable by group (unless group 0) or others, and must
  have no ACL. Symlinks are checked and then followed. This applies to the agent, sing-box, the control helper, the
  token, the state directory and `--cafile`. On Windows the same holds for SYSTEM, Administrators and
  TrustedInstaller. Above the directory that holds a file, creating new entries is tolerated (`C:\` allows it), but
  changing existing ones is not. Program files go to `C:\Program Files\CCProxyExit`.
- **Reruns.** Running the installer again is safe. Omitted options keep their previous values, and pressing Enter
  at the token prompt keeps the stored token. sing-box is downloaded only when its pinned digest changes. The last
  confirmed configuration stays in place.
- **Boot.** The services start at boot without a login. On Linux these are the systemd units
  `ccproxy-exit-singbox`, `ccproxy-exit-agent` and, with `--iface`, `ccproxy-exit-ips`. On macOS they are the launchd
  daemons `com.ccproxy.exit.singbox` and `com.ccproxy.exit.agent`. sing-box starts from the last confirmed config
  even when the control plane is unreachable. On Windows, the scheduled task `CCProxyExitAgent` runs at startup as
  SYSTEM, and sing-box starts once the agent has reached the control plane.

## Agent behaviour

The Go agent is a port of the current Python agent contract (merged PR #11). It uses ETag polling with a settle
window and a maximum delay. It runs `sing-box check`, stages the candidate in the state directory, and copies it to
the config file only for a reload. Each candidate gets its own Clash API secret and marker outbound. Only a sing-box
that lists the marker confirms the candidate. The heartbeat reports `config_etag`, `apply_state`
(`confirmed`/`pending`/`failed`/`unknown`), `apply_error`, `candidate_etag`, `singbox_running` and egress probes.
After a definitive failure, the agent restores the last confirmed config.

| Platform | Reload | Egress IPs |
| --- | --- | --- |
| Linux | `systemctl reload-or-restart ccproxy-exit-singbox` (SIGHUP) | With `--iface`, each routed IP the interface lacks is added as `/32` and recorded in `owned-ips.txt`. Addresses already present are left alone. `ips down` (uninstall, `--no-iface`) removes only recorded addresses. The boot unit runs `ccproxy-exit-agent ips up` before sing-box |
| macOS | `launchctl kill SIGHUP` (or `kickstart` before the first config) | The Mac's existing local IPv4; no IP helper |
| Windows | `--run --run-reload restart`: sing-box is stopped and started again (no SIGHUP), then confirmed like any reload | The host's existing address |

## Entry address and local bind IP

These are two different addresses. Keeping them apart is what makes a Mac behind home NAT work.

| Setting | Meaning | Mac mini behind NAT |
| --- | --- | --- |
| Host **public entry address** (`public_host`) | Where clients connect: sing-box listens on all interfaces at each user's entry port | The router's public IPv4 or a DNS name for it. Forward the host's TCP port range on the router to the Mac |
| Host **egress IP** (IP inventory) | The local address sing-box binds outgoing connections to (`inet4_bind_address`), and the source of the egress probes | The Mac's own LAN IPv4, for example `192.168.1.20` (`ipconfig getifaddr en0`). Reserve it in the router's DHCP |
| Observed public IPv4 | What websites see | The router's WAN address (or the ISP's CGNAT address). It is not configured anywhere |

## macOS acceptance (Mac mini)

1. In the console, open **Egress hosts → Add host**. Set **Public entry address** to the router's public IP or DNS
   name. Use a port range that the router forwards (TCP) to the Mac. The dialog that follows shows the agent token
   **once**. Copy the token into a password manager before you close the dialog, because adding the egress IP means
   leaving it. The token cannot be shown again; if it is lost, rotate it.
2. Close the dialog. On the host page, use **Add IPs** to add the Mac's LAN IPv4 (`ipconfig getifaddr en0` on the
   Mac, reserved in the router's DHCP). Assign a test user to that IP. In **Settings → split rules**, make sure the
   domains that go through the proxy include `api.ipify.org` (for example `"domain_suffix": [..., "api.ipify.org"]`).
   Without it, the client's check in step 5 goes out directly and proves nothing.
3. On the Mac mini, open **Install command → macOS** on the host page and copy the command. Paste it into Terminal
   and enter the Mac password for `sudo`. Then paste the saved token at the hidden prompt. The installer ends with
   `installed.`. If the macOS application firewall is on, run the two `socketfilterfw` commands it prints. To keep
   the node awake and powered back on after an outage, run `sudo pmset -a sleep 0 autorestart 1`.
4. Check the services:
   ```bash
   sudo launchctl print system/com.ccproxy.exit.agent | grep -E 'state|pid'
   sudo launchctl print system/com.ccproxy.exit.singbox | grep -E 'state|pid'
   sudo tail -n 20 /var/log/ccproxy-exit/agent.log      # expect "sing-box confirmed running config version ..."
   ```
   In the console, the host shows a fresh heartbeat, **in sync**, apply state **confirmed**, and sing-box
   **running**. The egress probes for the Mac's LAN IP succeed.
5. Check the observed public IPv4. On the Mac, run `curl -4 https://api.ipify.org`. On a client signed in as the
   test user, outside the home network, open `https://api.ipify.org` through CC Proxy. Both should show the same
   address: the router's public IPv4. If the client shows its own network's address instead, check the split rule
   from step 2.
6. Check boot recovery, **only if you can unlock or recover the Mac when a reboot stops at a prompt**: someone on
   site, remote console access, or FileVault turned off. Do not reboot an unattended remote Mac by default. With
   FileVault on, a normal restart waits at the unlock screen and no service starts until someone unlocks the disk.
   `sudo fdesetup authrestart` skips that prompt for one restart, but treat it as a planned operation with a
   recovery path. After the restart, do **not** log in. From the console, confirm that the heartbeat resumes, the
   host is in sync, and sing-box is running. Repeat step 5. If you cannot recover the Mac remotely, skip this step
   and run it the next time someone is on site. The launchd daemons need no login either way.
7. Optional: rotate the token in the console and save the new one. Rerun the install command, paste the new token,
   and confirm that the heartbeat resumes. Run the command once more and press Enter at the prompt to confirm that
   a rerun keeps the token.

### macOS uninstall

1. Copy the **macOS uninstall** command from the console (Install command → macOS) and run it on the Mac.
2. Check that nothing is left:
   ```bash
   sudo launchctl print system/com.ccproxy.exit.agent     # "Could not find service"
   ls /opt/ccproxy-exit /etc/ccproxy-exit /var/lib/ccproxy-exit /Library/LaunchDaemons/com.ccproxy.exit.*  # all missing
   ```
3. In the console, delete the host, or rotate its token if it will be reinstalled. The stored token on the Mac was
   removed with the rest.

## Linux and Windows

- **Linux.** Use the same command with `--iface eth0` only when the provider routes extra egress IPs to the host.
  Logs: `journalctl -u ccproxy-exit-agent -u ccproxy-exit-singbox`. Uninstall stops `ccproxy-exit-ips`, which takes
  the IPs off the interface, then removes the units and files.
- **Windows.** Run the command in PowerShell started with **Run as administrator**. The control-plane certificate
  must be trusted by Windows (a public CA, or your CA in `LocalMachine\Root`). The agent log is
  `C:\ProgramData\CCProxyExit\logs\agent.log` (5 × 10 MB). Uninstall removes the task, the firewall rule and both
  directories.

## Tests

```bash
(cd egress/agent && go test ./...)                                  # Go agent unit tests (17)
egress/agent/build.sh --verify                                      # reproducible cross-build, 6 targets
cd controlplane && python3 -m unittest tests.test_installer tests.test_go_agent -v
```

| Test | Covers | OS paths run here |
| --- | --- | --- |
| `egress/agent/*_test.go` | Routed-IP ownership (a pre-existing address survives up and down), confirm/marker contract, SIGHUP and restart reloads, rejected version, rollback after a crash, a stubborn process, reload command, settle window, redirect refusal, the HTTPS rule, probes bound to a source IP, log rotation | macOS arm64 native; `go vet` for all six targets |
| `tests/test_go_agent.py` | The compiled agent against the real control plane: SIGHUP reload, Windows-style restart reload, rejected version, `http://` refused. Uses `fake_singbox.py`, or the official binary when `CCPROXY_TEST_SINGBOX` is set | macOS arm64 native, run with both the fake and the pinned sing-box 1.14.4 |
| `tests/test_installer.py` | Commands (HTTPS-only, full-string validation, exit status 22/7 kept, temp file removed); public and token-gated assets; tamper → 503; console flow; rendered `exit.sh` end to end over real TLS: macOS (plists checked with `plutil`), Linux mode (`--iface` units), rerun, uninstall, wrong token, digest mismatch, redirect plus `.curlrc` `location`, untrusted root | macOS native with BSD tools; Linux mode with stubbed `systemctl` on macOS |
| Docker `debian:12-slim` (linux/arm64, `NET_ADMIN`) | `ccproxy-exit-agent ips up/down` with the real `ip` tool on a dummy interface: a pre-assigned 192.0.2.20 survives, 192.0.2.21 is added and removed | Linux arm64 (manual run, not in the unit suite) |
| PowerShell 7.4 parser (Docker) | `exit.ps1` as served, both Windows commands, the data block, `\z` patterns | Parse only; Windows PowerShell 5.1 and the Windows task were not run |

Not exercised here: a real `launchctl` or `systemctl` load, a Windows host (Windows PowerShell 5.1, the scheduled
task, ACLs) and a reboot. On the Mac mini, macOS acceptance steps 3–7 cover the launchd load and, when it is safe,
the reboot. A Windows host still needs its own manual run.
