# Control plane

The Go control plane manages exit hosts, egress IPs, users, devices, and sing-box configurations in PostgreSQL. Existing desktop clients, agents, probers, and `cpctl` use the HTTP API. Use [egress/gen.py](../egress/gen.py) to render configurations from offline inventory files.

| Component | Purpose |
| --- | --- |
| `main.go`, `http.go`, `admin_http.go` | Service commands, HTTP routes, and the embedded browser console |
| `schema.sql`, `store.go` | PostgreSQL tables, transactions, settings, and configuration version |
| `allocation.go`, `users.go` | Host, IP, port, user, and device management |
| `config.go` | sing-box configurations and content ETags |
| `auth.go` | Administrator accounts, sessions, CSRF, password verification, and audit log |
| `monitor.go`, `alerts.go` | Agent heartbeats, probes, topology, alerts, and webhooks |
| `migration.go`, `sqlite_export.py` | One-time SQLite v2 import |
| `agent.py`, `prober.py`, `cpctl.py` | Exit host synchronization, vantage probes, and administration |

## Run the server

Build with Go 1.25 or newer. Prepare a PostgreSQL database and give the service role permission to create and manage tables in the target schema. The Docker test suite uses PostgreSQL 16.

```bash
cd controlplane
go build -o cc-controlplane .
export DATABASE_URL='postgres://ccproxy:YOUR_PASSWORD@127.0.0.1:5432/ccproxy?sslmode=disable'
./cc-controlplane init --settings /path/to/settings.json --admin admin
export CP_PROBE_TOKEN=$(openssl rand -hex 24)  # Optional, for vantage probes
export CP_ADMIN_TOKEN=$(openssl rand -hex 24)  # Optional, for cpctl and scripts
./cc-controlplane serve --listen 0.0.0.0 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

`init` prints the generated admin password once. The optional settings file can set `client_policy`, `cooldown_seconds`, `monitor`, and `alerts`. Update them later with `PUT /admin/settings`. The `--db` flag can supply the connection string in place of `DATABASE_URL`. For a remote PostgreSQL server, use `sslmode=verify-full` with a trusted certificate.

For a TLS-terminating reverse proxy, pass each trusted address or CIDR with `--trusted-proxy`, or set the comma-separated `CP_TRUSTED_PROXIES` environment variable. The service uses `X-Forwarded-For` and `X-Forwarded-Proto` from trusted peers for login rate limits, audit addresses, and secure cookies.

Create additional administrators in the console or run `./cc-controlplane admin-add NAME`. The command reads `CP_ADMIN_PASSWORD` or prompts in a terminal. `serve` requires an administrator account or `CP_ADMIN_TOKEN`.

From the repo root, run `docker build -t cc-controlplane controlplane` to build a runtime image. It embeds the console, connects using `DATABASE_URL`, and listens on port 8443 by default.

## Import SQLite v2 data

Stop the old control plane and back up its SQLite database. Point `DATABASE_URL` at an empty PostgreSQL database. Run the migration from a host with Python 3.8 or newer for SQLite access.

```bash
./cc-controlplane migrate-sqlite /path/to/cp.db
./cc-controlplane serve --listen 127.0.0.1 --port 8443
```

The importer opens a read-only SQLite snapshot and copies it in one PostgreSQL transaction. It preserves password hashes, Reality keys, IP and port assignments, device and agent tokens, administrator sessions, settings, and monitoring, alert, and audit records. Carry over the service URL, `CP_ADMIN_TOKEN`, `CP_PROBE_TOKEN`, and TLS or reverse proxy settings. Check the global version at `/healthz` and verify that existing credentials still work. A SQLite v1 database must first be converted to the v2 data model.

## Allocation and access

- A host has a public entry address, a Reality key pair, a port range, and a rotatable agent token. Each egress IPv4 address belongs to one host. Each assigned user gets one dedicated entry port on the host of their egress IP.
- `assign` accepts an optional IP, port, and host. Automatic selection takes the lowest available IPv4 address and the lowest free port in that host's range. Ports can repeat across different hosts. `reassign` moves a binding in one transaction and keeps the port on a same-host move when possible.
- IP states are `available`, `assigned`, `cooldown`, and `banned`. Sharing requires `shared` mode for every holder. The last release starts cooldown, which defaults to seven days. A ban releases all holders. `ip-available` ends cooldown or removes the ban.
- User and administrator passwords use salted PBKDF2-SHA256 with 200,000 iterations and an eight-character minimum. The server generates a password when one is omitted and returns it once.
- `POST /v1/login` accepts a username, password, device name, and optional platform. After ten failed attempts in ten minutes for the same account or client address, further attempts receive HTTP 429.
- A device has its own VLESS UUID and subscription token. The default limit is five active devices per account. Signing in again on an active device rotates its token and keeps its UUID. Administrators can revoke a device or revoke all devices during a password reset. The database stores hashes of bearer tokens.
- Agents can fetch only their own configuration and IP list and can report results for their host's egress IPs. Hosts reject IPv6 exit traffic. By default, they also reject private and cloud metadata destinations after resolving the destination domain.
- Configuration mutations increment the global version. `/v1/config?mode=app` and `/agent/server-config` return ETags derived from the rendered body. Requests with a current ETag get HTTP 304. The client configuration also supports `proxy` and `domain` modes.

## Administration

Open `/` in a browser, or point `cpctl` at the service.

```bash
export CP_URL=https://cp.example.com:8443
controlplane/cpctl.py host-add hk-1 203.0.113.2 www.example.com --ports 20000-20999
controlplane/cpctl.py ip-add hk-1 203.0.113.3 203.0.113.4
controlplane/cpctl.py user-add alice
controlplane/cpctl.py assign alice 203.0.113.3 --port 20007
controlplane/cpctl.py reassign alice --host jp-1
controlplane/cpctl.py passwd alice --revoke-devices
controlplane/cpctl.py revoke alice MacBook
```

Use a TLS 1.3 site as the Reality SNI and allow the host entry ports through its firewall. The console can manage hosts, IP inventory, user assignments, headless devices, settings, alerts, administrators, and audit history. Bulk IP entry accepts single addresses, ranges, and CIDR blocks from `/22` to `/32`.

Browser sessions use an `HttpOnly`, `SameSite=Strict` cookie with a 12-hour expiry and a hashed session token. TLS requests set `Secure`. Authenticated mutations require `X-CSRF-Token`. Administrator password changes invalidate their sessions. The console has a content security policy and forbids framing. Audit entries retain successful mutations and login attempts for 180 days, redact sensitive request fields, and use `api-token` as the actor for bearer-token administration.

## Exit agent

```bash
export CP_AGENT_TOKEN=YOUR_HOST_AGENT_TOKEN
controlplane/agent.py --cp https://cp.example.com:8443 --iface eth0 \
  --reload-cmd "systemctl reload sing-box" --status-cmd "systemctl is-active --quiet sing-box"
```

Use `--run` in a container to let the agent manage the sing-box process. The agent downloads the IP list and configuration, runs `sing-box check`, then atomically replaces the file and reloads. The first configuration is applied immediately. Later changes settle for `--settle` seconds (10 by default) and apply within `--max-delay` seconds (60 by default) during a steady stream of changes. A change that returns to the applied configuration skips a reload. Rejected configurations are remembered by ETag.

The agent adds a private Clash API listener to the candidate configuration on `--confirm-api` (loopback `127.0.0.1:9095` by default). Each candidate has its own API secret and an unused outbound tag. After reload, sing-box confirms the generation by returning that tag from `GET /proxies`. Use a sing-box build with Clash API support and keep the loopback port available.

On a definite reload failure the agent restores the last confirmed configuration and retries the candidate, including when the control plane returns HTTP 304. In `--run` mode it restarts a crashed sing-box with the last confirmed configuration. When sing-box returns no confirmation, the agent keeps the candidate on disk and reports `unknown`.

The agent reports the last confirmed configuration ETag, an `apply_state` of `confirmed`, `pending`, `failed`, or `unknown`, and the latest apply error. The console shows a host as synchronized when the ETag matches and the state is confirmed. Legacy agents that omit the state are evaluated by ETag.

### One-command install (Go agent)

New exit hosts use the compiled Go agent (`egress/agent`) and a one-command installer instead of a checkout and Python. **Add host**, **Rotate agent token** and a host's **Install command** button show copy-ready commands for macOS, Linux and Windows. The installer prompts for the agent token with hidden input, then downloads the agent and the pinned sing-box and verifies their SHA-256 digests. It installs boot services (launchd, systemd, or a SYSTEM startup task). The server embeds the install scripts and pins from `install/`, and serves agent binaries from the reproducible build named by `CP_AGENT_DIST`:

```bash
egress/agent/build.sh --verify                      # six OS/architecture binaries, SHA256SUMS, VERSION
CP_AGENT_DIST=$PWD/egress/agent/dist cc-controlplane serve ...
```

`GET /install/exit.sh`, `/install/exit.ps1` and `/install/manifest.json` are public. `GET /install/agent/{os}-{arch}` requires a host agent token, and `GET /admin/install-commands?cp=https://...` requires an administrator. The installer details and the Mac mini acceptance steps are in [the installer guide](../egress/install/README.md).

**XTCP transport.** A host behind NAT can use frp XTCP instead of a public entry: `GET/PUT/DELETE /admin/hosts/{name}/xtcp` (admin; the frps token and secret key are write-only) stores the frps address, TLS name and CA, token, proxy name, secret key and sing-box port in `host_xtcp`. With the host's agent token, `GET /install/xtcp/frpc.toml` and `/install/xtcp/ca.pem` return that host's frpc configuration (or 204), and the same install command then also installs the pinned frpc (`install/frpc.json`) as a boot service. Data flows directly between visitor and exit host; there is no relay fallback. Details in [the installer guide](../egress/install/README.md#xtcp-transport-hosts-behind-nat).

## Monitoring and topology

| Source | Results | Default frequency |
| --- | --- | --- |
| Agent heartbeat | Confirmed configuration ETag, apply status, and sing-box health | Every synchronization interval |
| Agent egress probe | HTTP GET bound to an egress IP, with time to response headers. Status 2xx or 3xx counts as success | 60 seconds |
| `prober.py` | Best latency of three TCP connection attempts from a named network | 30 seconds |

A vantage probe targets the lowest entry port in use on each host and any additional `monitor.entries` targets. Probe data is retained for seven days. The topology shows the latest 20 results per source and target. Probes and alerts have no effect on the configuration version.

```bash
curl -X PUT "$CP_URL/admin/settings" -H "Authorization: Bearer $CP_ADMIN_TOKEN" -d '{"monitor": {
  "egress_targets": ["https://www.example.com/"],
  "entries": [{"name": "hk-relay", "host": "198.51.100.1", "port": 443}]}}'
CP_PROBE_TOKEN=YOUR_PROBE_TOKEN controlplane/prober.py --cp "$CP_URL" --vantage sh-telecom
```

Topology refreshes every ten seconds. Search by host, entry, or egress IP. **Needs attention** surfaces failures and warnings. Select a host to see heartbeat, applied configuration, probe history, users, and devices. The IP inventory shows allocation and probe health separately. Results older than three minutes are stale.

## Alerts

Rules use the same topology data as the console. The default evaluation interval is 15 seconds.

| Rule | Condition | Severity |
| --- | --- | --- |
| `egress_probe_failing` | An unbanned egress IP fails `consecutive_failures` consecutive probes to a target. The default is 3 | Critical with assigned users, otherwise warning |
| `entry_unreachable` | A vantage fails consecutive probes to an entry | Critical when all reporting vantages fail, otherwise warning |
| `agent_stale` | No heartbeat for more than `agent_stale_seconds`, which defaults to 120 | Critical |
| `singbox_down` | The agent reports that sing-box has stopped | Critical |
| `agent_out_of_sync` | The applied and current ETags differ for `out_of_sync_seconds`, which defaults to 300 | Warning |

Alerts enter `pending` during any grace period and become `firing` once it expires. Recovery changes a firing alert to `resolved` and cancels alerts that are still pending. Resolved alerts are kept for 30 days. Webhooks send on firing and resolution, with optional reminders through `repeat_seconds`. Partial delivery failures retry the batch. The console shows webhook delivery errors.

```bash
curl -X PUT "$CP_URL/admin/settings" -H "Authorization: Bearer $CP_ADMIN_TOKEN" -d '{"alerts": {
  "webhooks": [{"url": "https://open.feishu.cn/open-apis/bot/v2/hook/...", "format": "feishu"}],
  "consecutive_failures": 3, "agent_stale_seconds": 120}}'
controlplane/cpctl.py alert-test
controlplane/cpctl.py alerts --all
```

Webhook formats include `generic` JSON and text payloads for Slack, Feishu, DingTalk, and WeCom. Operators can ban an IP through the console or `cpctl`.

## Tests

From the repo root, set `TEST_DATABASE_URL` to a dedicated PostgreSQL test database. Both suites create temporary schemas. The Python HTTP suite uses `psql` to manage its test schemas and runs the Go binary.

```bash
export TEST_DATABASE_URL='postgres://ccproxy:YOUR_PASSWORD@127.0.0.1:5432/ccproxy_test?sslmode=disable'
go -C controlplane test -race ./...
python3 -m unittest discover -s controlplane/tests -v
controlplane/test/run-e2e.sh  # Docker, set KEEP=1 to keep the containers
```

The Docker test provisions two exits through the admin API, verifies assigned and shared IPs, checks agent configuration and probes, and verifies webhook delivery. It runs the Rust client with a Linux TUN through sign-in, a cross-host reassignment, and device revocation. For the local desktop demo, use `client/test/local-demo/up.sh`. Set `CP_DEMO_PORT` to choose a host port when 18450 is in use.

## Operational limits

A sing-box reload drops existing connections on that exit host. Removing an IP from inventory leaves its interface address in place. The host firewall still needs the entry range configured. All console administrators have the same permissions. Alert messages sent to external services can include IP addresses and usernames. Restart the server to load a new TLS certificate when terminating TLS directly.
