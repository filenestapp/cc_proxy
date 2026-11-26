# aifree client

The GUI and terminal client sign in with a customer email or proxy username, receive the device's assigned exit, and apply the control plane's routing policy. Matching traffic uses the exit. Other traffic keeps using the local network.

| Directory | Purpose |
| --- | --- |
| `core/` | Sign-in, session storage, config sync, elevation, and supervision shared by both frontends |
| `cli/` | The `aifree` command and the tunnel and XTCP visitor helpers |
| `desktop/` | Tauri GUI, desktop installers, and their updater |
| `macos/` | Legacy domain-mode resolver scripts |

## Install on a headless Linux host

Download the versioned Linux CLI archive and its checksum from the release. Choose `linux-x86_64` or `linux-arm64`. The archive contains the CLI and pinned `sing-box` and `frpc` executables. Use a glibc-based Linux distribution such as Debian 12 with the corresponding CPU architecture and `/dev/net/tun`. The bundled sing-box uses the system glibc loader. Install `sudo` and authorize TUN setup for the client user.

```sh
package=aifree-cli-0.2.3-linux-x86_64   # Use the name of the downloaded release.
sha256sum -c "$package.tar.gz.sha256"
sudo mkdir -p /opt/aifree-cli
sudo tar -oxzf "$package.tar.gz" -C /opt/aifree-cli
sudo ln -s "/opt/aifree-cli/$package/aifree" /usr/local/bin/aifree
aifree --version
```

For an upgrade, verify and extract the new archive into its versioned directory. Disconnect the client and repoint the installed link to that directory before reconnecting.

## Use the terminal client

Run the client as the OS user that owns the device session. On macOS and Linux, `connect` invokes `sudo` for the tunnel supervisor. On Windows it prompts through UAC. The signed-in user retains ownership of config sync and the XTCP visitor.

```sh
aifree login --user user@example.com
aifree connect
# In another terminal:
aifree status
aifree disconnect
aifree logout
```

The login command prompts without echoing the password. In a script, pipe the password through standard input or provide `AIFREE_PASSWORD` from the environment. The default control plane is `https://cp.aifree.sg`. Use `--server` to select a different endpoint for sign-in, or set `AIFREE_CONTROL_PLANE_URL` for both frontends. The saved session uses its original endpoint.

`connect` runs in the foreground and supports both public and XTCP exits. Stop it with Ctrl-C or `aifree disconnect` from another terminal. An XTCP connection reports running after its visitor establishes the direct path. A revoked device loses its session and the tunnel stops. Existing scripts can switch to the `aifree` executable and retain `login --server`, `up`, `sync`, `status`, and `logout` syntax. `up` retains the legacy privileged, manually managed tunnel behavior. `CCPROXY_PASSWORD` remains an accepted login environment variable.

### Run with systemd

Use a dedicated, unprivileged service account and a state directory owned by that account. Use the same state directory for login and service commands.

```sh
sudo install -d -m 0700 -o aifree -g aifree /var/lib/aifree-client
sudo -u aifree /usr/local/bin/aifree --state-dir /var/lib/aifree-client login --user user@example.com
```

Authorize the exact supervisor command in `sudoers` so the service can start without a terminal. With sudo 1.9.10 or newer, the argument regex below allows the generated connection ID while pinning the paths and the supervisor mode. Use `visudo -f /etc/sudoers.d/aifree-client` and substitute the version, architecture, and state directory for your installation.

```sudoers
aifree ALL=(root) NOPASSWD: /opt/aifree-cli/aifree-cli-0.2.3-linux-x86_64/aifree ^--state-dir /var/lib/aifree-client tunnel --singbox /opt/aifree-cli/aifree-cli-0[.]2[.]3-linux-x86_64/sing-box --heartbeat-timeout 60 --connection-id [0-9a-f]{32}$
```

Save the unit as `/etc/systemd/system/aifree-client.service`.

```ini
[Unit]
Description=aifree client
Wants=network-online.target
After=network-online.target

[Service]
User=aifree
ExecStart=/usr/local/bin/aifree --state-dir /var/lib/aifree-client connect
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Start with `sudo systemctl enable --now aifree-client`, stop with `sudo systemctl stop aifree-client`, and read the service log with `journalctl -u aifree-client`. Run `status` as the service user with `--state-dir /var/lib/aifree-client`.

## Use the desktop build

On macOS, open **Install aifree.pkg** inside the DMG to install the app and register `/usr/local/bin/aifree`. The Windows installer adds the app directory to the current user's PATH. Debian packages install `/usr/bin/aifree`. Open a fresh terminal after installation and run `aifree --help`.

The portable Linux AppImage exposes the same CLI through its `cli` entry point. Extract-and-run also makes the bundled executables available to the privileged supervisor.

```sh
APPIMAGE_EXTRACT_AND_RUN=1 ./aifree.AppImage cli --help
APPIMAGE_EXTRACT_AND_RUN=1 ./aifree.AppImage cli connect
```

The GUI and terminal share the current OS user's device session and tunnel state. Connect from either surface and disconnect from either. An active or stopping connection holds the connection lock until cleanup completes. Closing a GUI that is observing a CLI connection leaves the CLI in control.

The desktop home screen shows the account, device, connection state, and verified public exit IPv4. Choose **System**, **English**, or **Simplified Chinese** for language and **System**, **Light**, or **Dark** for appearance. The tray keeps the app running when the window closes on a supported desktop. Select **Quit aifree** to stop a GUI-owned connection and exit.

The bundle identifier is `sg.aifree.desktop`. macOS treats it as a new app relative to the old CC Proxy bundle. Open **Environment check** for exit, DNS, network, and TLS measurements. The Rust client uses the [Netcheck report interface](https://netcheck.wenbo.io/cli) for reputation and findings. It submits observed addresses, language, time zone, OS version, and timings. Local routes, adapters, configured proxies, and certificates appear in the local result.

## Connection behavior

- The control plane issues a revocable token per device. The client stores it in the existing `cc-proxy/session.json` user config directory with mode 0600 on Unix.
- The frontend fetches app-mode sing-box settings and uses ETags for subsequent config checks. A changed assignment reloads the tunnel. Revocation, a lost assignment, and sign-out stop it.
- The privileged supervisor validates and re-renders the user-side settings into its protected runtime directory before running sing-box. It stops on the stop request, missing config, or a stale frontend heartbeat. It uses the same boundary for reloads and restarts.
- The supervisor keeps its logs and validated configuration in `/Library/Application Support/CCProxy` on macOS, `/var/lib/ccproxy` on Linux, and `%ProgramData%\CCProxy` on Windows.
- The TUN handles routing and DNS. Rule domains use fake IPs, local networks stay direct, and rule traffic falls back to TCP when QUIC is blocked. On macOS the supervisor sets per-domain resolvers after TUN setup and restores them on stop. The client refreshes the DNS cache when the tunnel starts, reloads, and stops.

### WebRTC and STUN

In app mode, compatible clients request `stun=1` from the control plane. The default policy sends new UDP flows that start with an RFC 5389 STUN message through the exit, regardless of destination port. STUN on UDP 443 takes precedence over the QUIC block. The dual-stack TUN captures IPv6 internet traffic, and the IPv4-only exit refuses IPv6 destinations. The Linux supervisor enables sing-box's native packet redirection so sockets bound to an interface address also reach the TUN.

An administrator can update `client_policy.stun` in the console under **Settings → Client routing policy → WebRTC (STUN)** or via `PUT /admin/settings` with `{"client_policy":{"stun":"reject"}}` (substitute the desired value). The client applies the policy during config sync.

| Value | Behavior |
| --- | --- |
| `proxy` (default) | Route UDP STUN through the exit. IPv4 STUN servers see the exit address. IPv6 STUN receives no answer. |
| `reject` | Drop UDP STUN at the client. |
| `direct` | Use the original split routing and IPv4-only TUN. Unmatched STUN can reveal the device's own address. IPv6 follows the platform's legacy behavior. |

While connected, **Environment check → UDP and STUN** reports **Exit** when a returned address matches the verified public exit, **Leak** when it differs, or **No answer** when no address is returned. An address comparison requires a verified exit for the route being tested.

The bundled frpc executable uses direct IPv4 STUN for XTCP hole punching. The supervisor limits that exception to its installed executable path on an XTCP connection. Local WebRTC host candidates, STUN over TCP or TLS, messages without the RFC 5389 magic cookie, and flows that began before Connect are outside this protection. Domain and local-proxy modes use their original routing. Deploy the control plane first, then release clients that declare support. Older clients receive their original configuration and require an update to enable the protection.

Linux also filters outgoing STUN after the kernel selects the network interface. A socket forced onto a physical interface gets no answer when its packets cannot enter the TUN. This protection requires the kernel's nftables owned-table support, available in Linux 5.15 and later. The kernel removes the filter when the tunnel supervisor exits.

### XTCP exits

For an exit behind NAT, the CLI and GUI fetch device-scoped visitor settings from `/v1/xtcp-visitor`. The unprivileged frontend starts the bundled frpc after TUN routes are ready, because the UDP path must be established with the active routes. It reports running after frpc opens the direct path. The visitor receives the token through its environment and redacts it from logs. Disconnect, sign-out, or frontend exit stops the guard and frpc.

The privileged supervisor manages sing-box. The unprivileged visitor handles XTCP. Both frontends use the same validation and retry behavior. A control plane from before the visitor endpoint returns 404 and continues to support public exits and manually configured visitors.

## Build and verify

```sh
cd client
cargo test --locked -p aifree-cli -p ccproxy-core
desktop/scripts/fetch-binaries.sh                 # Build aifree and verify the pinned sidecars.
cd desktop/src-tauri
npx --yes @tauri-apps/cli@2.12.6 build --bundles app  # macOS. Windows uses nsis, Linux uses deb/appimage.
```

The desktop release workflow builds the platform installers and the standalone Linux x86_64 and ARM64 archives. See [desktop release and update instructions](../docs/desktop-updates.md) for packaging and publication.

The Linux [direct exit suite](../controlplane/test/run-e2e.sh) exercises the CLI sign-in and TUN, routing, IPv4 and IPv6 STUN, assignment changes, and revocation. Run the [XTCP suite](../controlplane/test/xtcp/run-e2e.sh) with `AIFREE_CLIENT_ONLY=1` to test CLI connect with real frpc, routed traffic, duplicate connection prevention, disconnect and crash cleanup, token rotation, and revocation.

Earlier Apple silicon GUI acceptance exercised authorization, rule-domain traffic through the assigned exit, direct traffic, configuration reload, and cleanup after quitting. Use a domain such as `echo.example.com` for macOS DNS tests because the platform resolves the special-use `.test` suffix locally. Windows UAC, Linux polkit, and the desktop routes for XTCP remain platform acceptance checks.
