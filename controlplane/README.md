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
| `usage.go` | Per-device usage reports from exit agents and the admin usage view |
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

## aifree domains and cutover

One control-plane process serves the following public names. Route by the original `Host` header; do not use a redirect for API traffic.

| Host | Routes |
| --- | --- |
| `cp.aifree.sg` | Client and exit-agent APIs, installers, and the administrator console |
| `app.aifree.sg` | Customer `/v1/account/*` API and the future customer center at `/account` |
| `ccproxy.macmini.sg` | The same client, agent, installer, and administrator routes as `cp.aifree.sg` during migration |

Other hosts intentionally retain the previous unrestricted routing. This keeps localhost development, direct test requests, and private deployment names working. The configured aifree hosts are the only hosts that enforce the public split.

Install commands default to the configured public control-plane URL, not the browser's request URL. The administrator console pre-fills that URL and can send a validated HTTPS `cp` override when an existing control plane must remain reachable during a DNS cutover. Set `CP_PUBLIC_URL` or pass `--public-url`; it must be an HTTPS URL and defaults to `https://cp.aifree.sg`. Until the new DNS resolves, keep `CP_PUBLIC_URL=https://ccproxy.macmini.sg`.

```bash
CP_PUBLIC_URL=https://cp.aifree.sg \
  cc-controlplane serve --listen 127.0.0.1 --port 8443 \
  --trusted-proxy 127.0.0.1/32
```

Use the flag for a one-off deployment override:

```bash
cc-controlplane serve --public-url https://cp.aifree.sg
```

### Deployment and cutover

1. Create DNS `A`/`AAAA` (or proxied equivalent) records for `cp.aifree.sg` and `app.aifree.sg` that reach the same reverse proxy as the control plane. Leave `ccproxy.macmini.sg` pointed at that proxy.
2. Obtain and install a certificate covering all three names. Configure the reverse proxy to pass the original `Host`, plus `X-Forwarded-For` and `X-Forwarded-Proto`. Start the control plane with the proxy addresses in `--trusted-proxy` or `CP_TRUSTED_PROXIES` so secure cookies and audit addresses are interpreted correctly.
3. Set `CP_PUBLIC_URL=https://cp.aifree.sg`, deploy, and check the public routes: `https://cp.aifree.sg/console`, a desktop login and agent heartbeat against `cp.aifree.sg`, and a customer API request against `https://app.aifree.sg/v1/account/...`. Check that an install command generated from the console embeds `https://cp.aifree.sg`.
4. Roll out a desktop release whose sign-in field defaults to `https://cp.aifree.sg`. New exit-agent installation commands will use that URL. Existing desktop sessions and agents must continue using `ccproxy.macmini.sg` without a redirect.
5. Retire the old host only after the agent inventory shows every exit has been reinstalled or explicitly reconfigured to `cp.aifree.sg`, supported desktop clients have migrated, and the old-host access logs have remained unused for an agreed observation period. Then remove the old DNS record and its certificate name in a later deployment; do not retire it merely because the new hosts are healthy.

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
- IP states are `available`, `assigned`, `cooldown`, and `banned`. Sharing is opt-in: every holder of a shared IP must be in `shared` mode, and new users default to `exclusive`. `PUT /admin/users/{name}` with `{"mode": "shared"}` (or `cpctl.py user-mode NAME shared`) switches an existing user and keeps the IP, entry port, and device credentials. Switching back to `exclusive` succeeds only when the user holds the IP alone or holds none; otherwise it returns HTTP 409 and changes nothing. Each holder of a shared IP has its own entry port, so a host serves at most as many users as its port range has ports. Releasing, moving, or revoking one holder leaves the others unchanged. The last release starts cooldown, which defaults to seven days. A ban releases all holders. `ip-available` ends cooldown or removes the ban.
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

New proxy users default to shared egress mode. Select Dedicated egress IP in the console, pass `--exclusive` to `cpctl.py user-add`, or set `"mode":"exclusive"` in the admin API to create a dedicated user.

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

Managed automatic updates of installed agents read signed releases from `CP_AGENT_RELEASES` (one directory per
release, the exit-agent workflow's artifact) and roll one out to chosen hosts: `cpctl.py agent-releases`,
`agent-rollout`, `agent-rollout-set VERSION HOST... | --all`, `agent-rollout-pause|resume|clear`. See
[docs/exit-agent-updates.md](../docs/exit-agent-updates.md).

`GET /install/exit.sh`, `/install/exit.ps1` and `/install/manifest.json` are public. `GET /install/agent/{os}-{arch}` requires a host agent token, and `GET /admin/install-commands?cp=https://...` requires an administrator. The installer details and the Mac mini acceptance steps are in [the installer guide](../egress/install/README.md).

**XTCP transport.** A host behind NAT can use frp XTCP instead of a public entry: `GET/PUT/DELETE /admin/hosts/{name}/xtcp` (admin; the frps token and secret key are write-only) stores the frps address, TLS name and CA, token, proxy name, secret key and sing-box port in `host_xtcp`. With the host's agent token, `GET /install/xtcp/frpc.toml` and `/install/xtcp/ca.pem` return that host's frpc configuration (or 204), and the same install command then also installs the pinned frpc (`install/frpc.json`) as a boot service. Data flows directly between visitor and exit host; there is no relay fallback. The configured proxy forwards to `local_port` unchanged, and every other user on the host gets the proxy `<proxy_name>-<entry port>` with a secret key derived for that user from a server-held secret that is independent of the primary key and never leaves the control plane. `GET /admin/users/{name}/xtcp-visitor` returns that user's visitor configuration; it reads the frps token from `FRP_AUTH_TOKEN`. An upgraded agent keeps frpc in step by itself (`GET /agent/xtcp`, see `xtcp_sync.go`): every committed mapping change becomes a new generation, the agent applies it with a verified hot reload, confirms registration from frpc's live status, and reports the result in its heartbeat. The XTCP view's `sync` object and each mapping's `status` (`ready`, `pending`, `failed`, `upgrade_needed`) show it; a port is ready only once frpc registered it and sing-box confirmed its listener. `frpc_state` still tracks the installer's own fetch: `outdated` matters only for hosts whose agent predates mapping sync. Details in [the installer guide](../egress/install/README.md#xtcp-transport-hosts-behind-nat).

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

## Per-device usage

**Usage** in the console, `GET /admin/usage`, and `cpctl.py usage` show upload, download, and total bytes for each
client device per calendar day, week, or month. Periods use Asia/Singapore (UTC+8) and weeks start on Monday. Select
earlier periods with the arrows or the recorded-periods list, and filter by user and device. This is a report for
administrators only; billing, quotas, and alerts are separate.

```bash
controlplane/cpctl.py usage --period week --date 2026-11-23 --user alice
curl "$CP_URL/admin/usage?period=month&date=2026-11-01" -H "Authorization: Bearer $CP_ADMIN_TOKEN"
```

**Source.** The exit agent measures traffic with the sing-box API service (`services[].type: "api"`, sing-box 1.14 and
later). It is part of every official sing-box build, unlike the V2Ray statistics API, which needs the
`with_v2ray_api` build tag. All six pinned 1.14.4 packages in `install/sing-box.json` (darwin, linux, and windows on
amd64 and arm64) contain the API service and reject `v2ray_api`. The agent adds the service to each candidate config
on a loopback port (`--usage-api`, default `127.0.0.1:9096`) with its own secret. It then follows the connection
stream, which carries the authenticated VLESS user name `<user>/<device>` and byte counts for each connection.

**Attribution.** The agent counts every connection separately and attributes only growth in its byte totals, so a
counter reset on reload cannot produce negative or repeated traffic. A connection that opens and closes between
two updates is still counted in full from its final totals. Several users on one egress IPv4 and several devices of
one user are told apart by the VLESS credential, not by address. Usage belongs to `devices.id`, which stays the same
when a device signs in again, when it is revoked and re-registered, and when its user moves to another exit. A
deleted device or user keeps its history under the names it had when an exit was first configured with it.

**Deleted and recreated accounts.** A deleted account recreated with the same user and device names gets new device
IDs, so the names alone cannot say which device moved a byte. The agent therefore also sends the SHA-256 of the
VLESS UUID behind each connection. It takes the UUID from the config file only after the running sing-box proves it
loaded that file (its Clash API lists the file's confirmation marker, checked within one sing-box instance). The
control plane records the hash of every credential it serves, so a delayed batch lands on the original device, even
when both accounts existed in the same hour. Usage reports carry the credential hash. The server configuration
keeps its existing VLESS user names and ETags.

A name-only report entry goes to a device when exactly one device served under those names on that exit existed
before the reported hour ended, allowing 5 minutes of clock difference. With multiple candidates or an unrecognized
credential, the bytes are counted as unresolved on the exit, and each candidate device shows that hour as incomplete.

**Period boundaries.** Bytes count in the UTC hour in which the exit observed them, and Singapore periods are made of
whole UTC hours. A long connection's traffic is split at each update, which arrives every 250 ms. A connection that
closes between updates counts in the hour in which it closed. Traffic that an exit recovers after a restart or a
disconnect counts in the hour in which it was recovered.

**Status.** Each device row shows one of these states:

| Status | Meaning |
| --- | --- |
| Measured | A collector covered the device; 0 B is a measured zero |
| Incomplete | Measured, with the reason listed: collection started during the period; sing-box ended while the collector was away (`gap`); more than 1000 connections closed during a disconnection (`overflow`); a reload cut live connections, so up to 250 ms of each is not counted (`cut`); traffic reported under its names could not be attributed to a device (`unresolved`) |
| Not measured | No collector covered the device, for example on an exit whose agent does not report usage, or before history began |

**Integrity.** An exit can add traffic only under its own name and only for devices its configuration carried
(recorded when the agent fetches the config). Other names, and a credential reported under names it was not served
with, are counted on the exit as rejected bytes. Bytes from
connections without a user are shown as unattributed. Reports are batches numbered per collector. The agent writes
each batch to its state directory before sending it and resends it unchanged until the control plane accepts it.
The control plane ignores a batch it has already stored, so duplicate reports and retries change nothing.

**Independence.** Collection and reporting (`POST /agent/usage`, every `--usage-interval` seconds) run apart from
configuration sync and heartbeats. They never block or fail a config. If the service cannot be added because sing-box
is older than 1.14, the port belongs to another program, or `--usage-api off` was set, the agent applies the config
without it and reports collection as unavailable. **Usage collection by exit** in the console shows each exit as
collecting, starting, error, stale (no report for five minutes), or unavailable. An exit whose agent predates usage
reports, including `agent.py`, keeps working and is listed as unavailable.

**Rollout.** Usage history starts when collection becomes available on an exit.

1. Deploy the control plane. It adds the usage tables, which a previous binary ignores on rollback.
2. Rebuild the agent (`egress/agent/build.sh --verify`) and serve it with `CP_AGENT_DIST`.
3. Run each exit's **Install command** again. The new agent reloads sing-box once with the API service. The pinned
   sing-box 1.14.4 does not change.
4. Confirm that **Usage collection by exit** shows the exit as collecting.

An agent that reaches a control plane without usage support keeps its batches for up to 30 days and sends them
after the upgrade.

## Stripe subscriptions

Checkout requires both `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` in the control-plane runtime.
Use separate Stripe sandbox and live credentials. The API key needs permission to create customers and
Billing Portal Sessions, create, read, and expire Checkout Sessions, and read Prices and subscriptions.

1. In Stripe, create a monthly CNY Price for each plan and configure the Customer Portal for the available plans.
2. In the admin console under **Plans**, enter the matching Stripe Price IDs and amounts. The seeded monthly
   prices are CNY 600 for Standard, CNY 1,500 for Premium, and CNY 400 for Residential IP. Use a new Stripe
   Price ID when changing the amount for new checkouts. Existing subscriptions keep their Stripe price.
3. Set up a Stripe webhook at `https://cp.aifree.sg/v1/stripe/webhook` using API version `2026-11-18.endive`.
   Subscribe to `checkout.session.completed`, `checkout.session.expired`, `checkout.session.async_payment_succeeded`,
   `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`,
   and `invoice.payment_failed`. Use its signing secret for `STRIPE_WEBHOOK_SECRET`.

Checkout and the Customer Portal return customers to `https://app.aifree.sg/account`. Payment confirmation, IP
assignment, and release follow webhook processing. Complete paid Team seats and retry waiting IP assignments on
the **Provisioning** page. Renewal failures receive a three-day grace period by default. To change it, set
`subscription_grace_seconds` through `PUT /admin/settings`.

Suspending a customer in the console revokes their device and console sessions, but does not cancel their Stripe
subscription or release its assigned IP. For a permanent ban, cancel the subscription in Stripe as well.

## Alerts

Rules use the same topology data as the console. The default evaluation interval is 15 seconds.

| Rule | Condition | Severity |
| --- | --- | --- |
| `egress_probe_failing` | An unbanned egress IP fails `consecutive_failures` consecutive probes to a target. The default is 3 | Critical with assigned users, otherwise warning |
| `entry_unreachable` | A vantage fails consecutive probes to an entry | Critical when all reporting vantages fail, otherwise warning |
| `agent_stale` | No heartbeat for more than `agent_stale_seconds`, which defaults to 120 | Critical |
| `singbox_down` | The agent reports that sing-box has stopped | Critical |
| `agent_out_of_sync` | The applied and current ETags differ for `out_of_sync_seconds`, which defaults to 300 | Warning |
| `subscription_waiting_ip` | A paid customer is waiting for an exclusive egress IP | Warning |

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
controlplane/test/shared-egress/run-e2e.sh  # Docker, real sing-box and frp: shared IPs on direct and XTCP hosts
```

The Docker test provisions two exits through the admin API, verifies assigned and shared IPs, checks agent configuration and probes, and verifies webhook delivery. It runs the Rust client with a Linux TUN through sign-in, a cross-host reassignment, and device revocation. For the local desktop demo, use `client/test/local-demo/up.sh`. Set `CP_DEMO_PORT` to choose a host port when 18450 is in use.

## Operational limits

A sing-box reload drops existing connections on that exit host. Removing an IP from inventory leaves its interface address in place. The host firewall still needs the entry range configured. All console administrators have the same permissions. Alert messages sent to external services can include IP addresses and usernames. Restart the server to load a new TLS certificate when terminating TLS directly.
