# Exit-node installer and Go agent

An exit host is added in the control-plane console and installed with one copied command. The node runs two
programs, both downloaded and checked by the installer:

| Program | Source | Integrity |
| --- | --- | --- |
| `ccproxy-exit-agent` | [`egress/agent`](../agent) (Go, standard library only), served by the control plane | SHA-256 from the reproducible build's `SHA256SUMS`, embedded in the served install script |
| `sing-box` 1.14.4 | Official GitHub release | SHA-256 pinned in [`controlplane/install/sing-box.json`](../../controlplane/install/sing-box.json) (same version as `client/desktop/scripts/fetch-binaries.sh`) |
| `frpc` 0.72.0 (XTCP hosts only) | Official frp release | SHA-256 pinned in [`controlplane/install/frpc.json`](../../controlplane/install/frpc.json), the digests GitHub publishes, matching the release's `frp_sha256_checksums.txt` |

The node needs no Go, Python or repository checkout. macOS and Linux need `curl` (and systemd on Linux); Windows
needs nothing beyond Windows PowerShell 5.1. The Python agent (`controlplane/agent.py`)
is unchanged and stays available to existing deployments and the Docker end-to-end tests.

## Build and publish the agent

```bash
egress/agent/build.sh --verify          # builds 6 targets twice and fails unless the results are identical
```

Output: `egress/agent/dist/ccproxy-exit-agent-{darwin,linux}-{arm64,amd64}`, `...-windows-{amd64,arm64}.exe`,
`SHA256SUMS` and `VERSION` (`agent-` plus the git tree hash of `egress/agent`, so a rebase or merge that leaves the
agent source alone gives the same files). The build pins the Go toolchain (`go.mod`), disables cgo, and uses
`-trimpath`, no VCS stamp and an empty build ID. CI (`.github/workflows/exit-agent.yml`) runs the Go tests and the
reproducibility check, then uploads `dist` as an artifact.

The Go control plane (`controlplane/installer.go`) embeds the install scripts and the sing-box pins
(`controlplane/install/`), and reads the agent binaries from the directory in `CP_AGENT_DIST`. Mount the verified
`dist` into the container, for example `-v /srv/ccproxy/agent-dist:/agent-dist:ro -e CP_AGENT_DIST=/agent-dist`.
Every request hashes the binaries against `SHA256SUMS`. If `CP_AGENT_DIST` is unset, or a binary is missing or
changed, `/install/*` answers 503 and names `build.sh`.

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
| macOS | `launchctl kill SIGHUP` (or `kickstart` before the first config) | The Agent registers the IPv4 of the default `enN` interface when the egress pool is empty |
| Windows | `--run --run-reload restart`: sing-box is stopped and started again (no SIGHUP), then confirmed like any reload | The host's existing address |

## XTCP transport (hosts behind NAT)

A host can use frp XTCP instead of a public entry. The exit host runs frpc next to sing-box. frpc registers one
`xtcp` proxy with the frps rendezvous service and forwards it to sing-box on `127.0.0.1:<entry port>`. The user's
machine runs the matching frpc visitor and points CC Proxy at the visitor's local port. frps only brokers the
rendezvous. The two machines punch a direct UDP path (QUIC) and the data flows between them. The exit side has no
relay option, and a visitor without `fallbackTo` closes the connection when hole punching fails. No traffic falls
back to frps.

| Setting (host page → **Transport** → **Configure XTCP**) | Notes |
| --- | --- |
| frps address and port | The rendezvous service, TCP 7003 by default |
| frps TLS server name and CA certificate (PEM) | The frps certificate is always verified against this CA (`transport.tls.trustedCaFile`) |
| frps token | Write-only; never shown again |
| XTCP proxy name | Must match the visitor's `serverName`; unique across hosts |
| XTCP secret key | Write-only; must match the visitor's `secretKey`. Leave it empty on the first save to generate one (shown once) |
| sing-box entry port | The user's entry port on this host, within the host's port range |

**Several users on one XTCP host.** The proxy above is the primary mapping and keeps its name, secret key and entry
port. Every other user assigned to the host, including users who share an egress IP, gets its own proxy
`<proxy name>-<entry port>` that forwards to that user's entry port. Its secret key is derived for that user from a
random server-held secret that is separate from the primary secret key and never leaves the control plane. A user's
visitor therefore opens only that user's entry port, and the primary visitor's key opens no other mapping. **Visitor config** on the
host page (or `GET /admin/users/{name}/xtcp-visitor`) shows the user's visitor configuration; frpc reads the frps
token from the `FRP_AUTH_TOKEN` environment variable. The exit host learns new mappings when its install command runs
again. Until then the host page shows **Run the install command again** and only the existing proxies work.

The install command does not change. With the host's agent token, the installer asks
`GET /install/xtcp/frpc.toml` and `GET /install/xtcp/ca.pem`. A 204 means the public entry, and nothing about the
ordinary install changes. A 200 makes the installer do the following:

- download the frpc from the pinned official frp release (`controlplane/install/frpc.json`, 0.72.0) and check its
  SHA-256;
- write the CA (`frp-ca.pem`);
- have frpc verify the configuration from the control plane;
- install it as `frpc.toml`, readable by root or SYSTEM only (it holds the frps token and the secret key);
- run frpc as a boot service: launchd `com.ccproxy.exit.frpc` (log `/var/log/ccproxy-exit/frpc.log`), systemd
  `ccproxy-exit-frpc`, or the SYSTEM task `CCProxyExitFrpc` (log `C:\ProgramData\CCProxyExit\logs\frpc.log`,
  with an inbound firewall rule for frpc so UDP hole punching works).

A rerun upgrades an existing installation in place and restarts frpc with the current configuration. After **Use
public entry**, a rerun stops frpc and removes its service, binary and credentials. Uninstall removes frpc together
with everything else.

### macmini-sg-208 acceptance (Apple Silicon, XTCP)

The MacBook already runs the visitor `ccproxy-208-visitor` on `127.0.0.1:20443` (`serverName =
"ccproxy-208-direct"`, QUIC, no `fallbackTo`), and CC Proxy uses that local entry. The 208 side needs the same frps
token, secret key and CA. They are in `~/.config/ccproxy-xtcp-208/208/frpc.toml` and `coordinator-ca.pem` on the
admin Mac; do not paste them into chat or tickets.

1. **Control plane.** Deploy a build that contains this change. On the `macmini-sg-208` host page, open
   **Transport → Configure XTCP** and enter:
   - frps address `43.156.58.218`, port `7003`, TLS server name `43.156.58.218`;
   - CA certificate: the contents of `coordinator-ca.pem`;
   - frps token: the `auth.token` value;
   - proxy name `ccproxy-208-direct`;
   - secret key: the `secretKey` value;
   - sing-box entry port `20443`.

   The page then shows "XTCP through frps (direct connections only, no relay fallback)", the CA subject, and
   `ccproxy-208-direct → 127.0.0.1:20443`. The user that CC Proxy signs in as must be assigned to 208 on entry port
   `20443`.
2. **On 208.** First check that no frpc from the old standalone archive is running: `pgrep -fl frpc` should print
   nothing, or stop that process. frps refuses a second proxy with the same name. Then open **Install command →
   macOS** on the host page, copy the command and run it in Terminal on 208. On this control plane it is:
   ```sh
   (f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL 'https://ccproxy.macmini.sg/install/exit.sh' -o "$f" && sudo sh "$f" --cp 'https://ccproxy.macmini.sg'; s=$?; rm -f "$f"; exit $s)
   ```
   Enter the Mac password for `sudo`, then paste the agent token at the hidden prompt. If the agent is already
   installed, press Enter to keep the stored token. The output includes `transport: XTCP (frpc proxy for sing-box;
   direct connections only, no relay)`, `downloading frpc 0.72.0 (darwin-arm64)` and `installed.`.
3. **XTCP registration on 208:**
   ```sh
   sudo launchctl print system/com.ccproxy.exit.frpc | grep -E 'state|pid'      # state = running
   sudo grep -E 'login to server success|start proxy success' /var/log/ccproxy-exit/frpc.log | tail -n 2
   sudo stat -f '%Sp %Su' /etc/ccproxy-exit/frpc.toml                            # -rw------- root
   sudo lsof -nP -iTCP:20443 -sTCP:LISTEN                                        # sing-box on 20443
   ```
   The MacBook visitor log stops reporting `xtcp server for [ccproxy-208-direct] doesn't exist`.
4. **Direct tunnel.** On the MacBook, start or restart the visitor and use CC Proxy. Its log
   (`~/.config/ccproxy-xtcp-208/macbook/frpc.log`) shows `establishing nat hole connection successful` with a
   `remoteAddr` that is 208's public address, not `43.156.58.218`. `grep -i fallback
   ~/.config/ccproxy-xtcp-208/macbook/frpc.toml` prints nothing. If hole punching fails, the visitor logs `make hole
   error` or `open tunnel error` and the connection closes; nothing is relayed.
5. **Public IPv4.** On 208, run `curl -4 https://api.ipify.org`. On the MacBook, with CC Proxy connected and
   `api.ipify.org` in the proxied split rule, open `https://api.ipify.org` (or run `curl -4 https://api.ipify.org`
   in a proxied app). Both addresses must be the same: 208's outbound IPv4.
6. **Boot recovery,** only if someone can unlock or recover 208 when FileVault prompts after a restart. After the
   restart, do not log in. Check that step 3 passes again and that step 5 still shows 208's IPv4. Skip this step
   otherwise.
7. **Uninstall,** if needed: run **Install command → macOS uninstall**. It also removes frpc,
   `/etc/ccproxy-exit/frpc.toml` and `frp-ca.pem`.

## Entry address and local bind IP

These are two different addresses. Keeping them apart is what makes a Mac behind home NAT work.

| Setting | Meaning | Mac mini behind NAT |
| --- | --- | --- |
| Host **public entry address** (`public_host`) | Where clients connect: sing-box listens on all interfaces at each user's entry port | The router's public IPv4 or a DNS name for it. Forward the host's TCP port range on the router to the Mac |
| Host **egress IP** (IP inventory) | The local address sing-box binds outgoing connections to (`inet4_bind_address`), and the source of the egress probes | The Mac's own LAN IPv4, for example `192.168.1.20` (`ipconfig getifaddr en0`). Reserve it in the router's DHCP |
| Observed public IPv4 | The source address the control plane sees in an authenticated Agent heartbeat | Usually the router's WAN address or the ISP's CGNAT address |

Leave **Public entry address** blank to learn and refresh the address from authenticated Agent heartbeats. The control
plane uses the public IPv4 it sees on the request, including addresses forwarded by its configured trusted proxies.
A manual entry is preserved. Before the first usable heartbeat, the host displays **Waiting for Agent IPv4**.
The Agent prefers IPv4 for control-plane requests and can fall back to IPv6 for management traffic. The observed
address still needs a reachable TCP entry port. Set a manual address if clients connect through a relay or a DNS name.

On macOS, the Agent checks the IPv4 default route and reports the address of its `enN` network interface when its
egress list is empty. The control plane registers one address for an empty pool and preserves every existing
entry, including banned entries. Use **Add IPs** to choose a different address or configure a tunnel interface.

New hosts start with `google.com` for the Reality TLS server name and the default handshake target. The exit host
must be able to reach the chosen TLS 1.3 server. A manual handshake target can be set on the host form.

## macOS acceptance (Mac mini)

1. In the console, open **Egress hosts → Add host**. Leave **Public entry address** blank to discover it when the
   Agent connects, or enter the router's public IP or DNS name manually. Use a port range that the router forwards
   (TCP) to the Mac. Copy the one-time Agent token into a password manager before you close the dialog.
2. On the Mac mini, open **Install command → macOS** on the host page and copy the command. Paste it into Terminal
   and enter the Mac password for `sudo`. Then paste the saved token at the hidden prompt. The installer ends with
   `installed.`. If the macOS application firewall is on, run the two `socketfilterfw` commands it prints. To keep
   the node awake and powered back on after an outage, run `sudo pmset -a sleep 0 autorestart 1`.
3. Refresh the host page after the first heartbeat. Confirm the Mac's LAN IPv4 appears under **Egress IPs**. Reserve
   the address in the router's DHCP and assign a test user to it. Add `api.ipify.org` under **Settings → Proxied domains**
   so the client routes the IPv4 test in step 5 through CC Proxy.
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
(cd egress/agent && go test ./...)                     # Go agent unit tests (17)
egress/agent/build.sh --verify                         # reproducible cross-build, 6 targets
cd controlplane && go test ./...                       # installer routes, rendering, digests, console (no database)
TEST_DATABASE_URL=postgresql://... python3 -m unittest tests.test_installer tests.test_go_agent -v
```

| Test | Covers | OS paths run here |
| --- | --- | --- |
| `egress/agent/*_test.go` | Routed-IP ownership (a pre-existing address survives up and down), confirm/marker contract, SIGHUP and restart reloads, rejected version, rollback after a crash, a stubborn process, reload command, settle window, redirect refusal, the HTTPS rule, probes bound to a source IP, log rotation | macOS arm64 native; `go vet` for all six targets |
| `controlplane/xtcp_test.go` | frpc configuration: xtcp proxy only, TLS always verified, no fallback or relay settings, each secret once; CA validation; safe TOML paths; frpc pins in both scripts; the official frpc accepts the configuration (`FRPC_TEST_BIN`) | macOS arm64 native, with frpc 0.72.0 |
| `controlplane/installer_test.go` | Commands (HTTPS-only, full-string validation, download before `sudo`, `curl -q`); rendered scripts carry the agent and sing-box digests; PowerShell CRLF and first-line guard; BSD grep limits; tamper or missing build → 503; the sing-box pin matches the desktop build; routes through the real router; the console's three commands and copy guard | macOS arm64 native |
| `tests/test_go_agent.py` | The compiled agent against the Go control plane and PostgreSQL: SIGHUP reload, Windows-style restart reload, rejected version, `http://` refused | macOS arm64 native |
| `tests/test_installer.py` (XTCP) | Admin settings validated, secrets write-only (also in the audit log), generated secret key shown once, agent routes scoped to the calling host (204 for a public-entry host); installer on an XTCP host: macOS upgrade from a public-entry install, `frpc.toml` 0600, frpc plist and unit, back to the public entry removes frpc, digest mismatch and rejected configuration change nothing. With genuine archives, the real frpc 0.72.0 is downloaded, checked and verifies the configuration | macOS native; Linux mode with stubbed `systemctl` |
| `tests/test_installer.py` | Against the Go control plane over real TLS: agent downloads need a host token (not the admin token) and match the digest; exit status 22/7 of the copied command; rendered `exit.sh` end to end for macOS (plists checked with `plutil`) and Linux mode (`--iface` units), rerun, uninstall, wrong token, digest mismatch, redirect plus `.curlrc` `location`, untrusted root. With `CCPROXY_TEST_SINGBOX_ARCHIVES`, the genuine sing-box 1.14.4 archives are downloaded and verified | macOS native with BSD tools; Linux mode with stubbed `systemctl` |
| `controlplane/test/xtcp/run-e2e.sh` (Docker, systemd, internet) | Real Go control plane and PostgreSQL, real frps 0.72.0 on TCP 7003 (TLS, test CA, token), a systemd Linux exit host installed with the copied command (agent, sing-box and frpc from GitHub, verified), real frpc visitor (QUIC) and sing-box client from the CC Proxy client config. Checks: registration, services enabled at boot, proxied IPv4 equals the exit host's egress IPv4, 20 MB transfer with no bytes at frps, blocked hole punching fails with no relay, recovery after a container reboot, uninstall | Linux arm64 (Docker Desktop) |
| `controlplane/test/shared-egress/run-e2e.sh` (Docker, internet) | Real Go control plane on a PostgreSQL test schema, real sing-box 1.14.4 and frp 0.72.0 (pinned, verified). Two shared users on a public-entry host and two on an XTCP host reach their own listeners concurrently from the same egress IPv4; a single-port XTCP host upgrades with its first mapping and visitor unchanged; a user's visitor key does not open another user's proxy; allocation conflicts and mode switches; releasing or revoking one holder leaves the other working | Linux arm64 (Docker Desktop) |
| Docker `debian:12-slim` (linux/arm64, `NET_ADMIN`) | `ccproxy-exit-agent ips up/down` with the real `ip` tool on a dummy interface | Linux arm64 (manual run) |
| PowerShell 7.4 parser (Docker) | `exit.ps1` as served, both Windows commands, the data block, `\z` patterns | Parse only; Windows PowerShell 5.1 and the Windows task were not run |

Not exercised here: a real `launchctl` or `systemctl` load, a Windows host (Windows PowerShell 5.1, the scheduled
task, ACLs) and a reboot. On the Mac mini, macOS acceptance steps 3–7 cover the launchd load and, when it is safe,
the reboot. A Windows host still needs its own manual run.
