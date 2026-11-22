# Fix the eight findings from the November 22 cc_proxy review

**Status** Fixed on 2026-11-22 and checked on macOS; Windows and Linux desktop checks are still open (see the end). **Scope** Four P1 findings and four P2 findings in the current client, exit agent, and control plane.

Claude Code can use this issue as the implementation brief. Work on the P1 items first. Preserve existing client and admin API contracts where possible. If the worktree already contains a fix, verify it against the relevant acceptance criteria before making further changes.

## CC-01 [P1] Protect privileged runtime files and configuration

The desktop app passes its user-writable state directory to the elevated supervisor. The supervisor opens the log and runtime paths with elevated privileges and runs sing-box against a configuration written by the unprivileged client. Validation and launch reopen that configuration separately. On macOS the elevation launcher also redirects output into the shared directory. [Supervisor](../client/core/src/supervisor.rs#L101) · [Elevation launcher](../client/core/src/elevate.rs#L44) · [Local state](../client/core/src/session.rs#L33)

Keep the privileged configuration, working files, and logs under platform-appropriate administrator ownership and permissions. Accept only the client fields or operations needed for the supported tunnel modes. Validate a protected configuration copy and use that same copy for launch and reload. Keep unprivileged status, heartbeat, and stop access narrowly scoped.

- [x] Privileged file operations stay within the protected runtime directory and reject unsuitable path ownership or path resolution.
- [x] The supervisor rejects unexpected configuration fields at the privilege boundary. Initial launch, reload, and restart consume a protected, validated configuration.
- [x] The desktop app can still show status and stop the tunnel. A stale heartbeat still shuts it down.

## CC-02 [P1] Confirm reload before acknowledging the applied ETag

The agent assigns `self.etag` when it replaces the configuration file, before it reloads sing-box. A simulated reload failure followed by another poll reproduced a `304` and no second reload attempt. The dashboard can then display the new ETag while the process still uses its previous device authorization and exit rules. [Install and reload](../controlplane/agent.py#L147) · [Heartbeat](../controlplane/agent.py#L101)

Track the candidate and the applied configuration separately. Keep a failed reload eligible for retry, including when the control plane returns `304` for the downloaded candidate. Report the candidate as applied only after the running service confirms acceptance. Preserve an explicit failed or unknown status when the running version cannot be confirmed.

- [x] A transient reload failure leaves the previous applied ETag visible, triggers another attempt, and advances the ETag only after success.
- [x] An invalid candidate leaves the last working configuration available. Multiple changes within the existing settle window still coalesce into one successful reload.
- [x] Tests cover both reload entry points, `--run` and `--reload-cmd`.

## CC-03 [P1] Keep probes off the configuration and heartbeat loop

The agent runs up to 16 HTTP probes concurrently, then waits for the entire batch before sending a heartbeat or starting the next synchronization cycle. With 200 IPs, one target, and the default 10-second timeout, a timed-out batch can take about 130 seconds. The default stale-agent threshold is 120 seconds, and configuration updates also wait for the probe batch. [Probe batch and report](../controlplane/agent.py#L90) · [Main loop](../controlplane/agent.py#L177) · [Alert defaults](../controlplane/alerts.py#L33)

Schedule probes independently with bounded concurrency and bounded result buffering. Keep heartbeats and configuration updates running on their own cadence. Report completed probes without requiring the whole batch to finish.

- [x] With a simulated slow round covering 200 IPs, heartbeats and configuration polls proceed before the round completes.
- [x] A configuration change can be applied while probes are pending. Slow rounds do not accumulate without a bound.
- [x] Probe failures and completed per-IP results remain visible in the dashboard and alert pipeline.

## CC-04 [P1] Enforce the IPv4-only egress policy on dual-stack hosts

The generated direct outbounds bind `inet4_bind_address`. DNS uses `ipv4_only`, which controls address resolution. The pinned sing-box version uses separate IPv4 and IPv6 dialers, so a connection with an IPv6 destination can use the host's default IPv6 source on a dual-stack exit. That falls outside the assigned IPv4 policy. [Generated server rules](../egress/gen.py#L181) · [Pinned upstream dialer](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/dialer/default.go#L198)

Enforce the supported address family on the server before selecting a user's bound outbound. Keep IPv4 source binding, private-address filtering, and the existing denial for unassigned users.

- [x] The generated IPv4-only exit policy rejects IPv6 destinations consistently.
- [x] Assigned IPv4 TCP and UDP traffic still uses the assigned source address. Existing private-address and unassigned-device checks pass.
- [x] The generated configuration passes `sing-box check` on the pinned version.

## CC-05 [P2] Change a user's exit assignment atomically

Updating a bound user currently takes `release` followed by `assign`. The review confirmed that a subscription poll between those operations receives `409`. The desktop app treats that response as a deliberate removal, stops the tunnel, and stops polling while disconnected. A successful subsequent assignment then requires the user to reconnect. [Assignment guard](../controlplane/store.py#L447) · [Subscription conflict](../controlplane/store.py#L622) · [Desktop handling](../client/desktop/src-tauri/src/main.rs#L219)

Expose a single reassignment operation through the admin API and CLI. Validate the replacement host, IP, and port before committing the change. Update the binding and any applicable cooldown together in one transaction. Preserve the explicit release action and its existing client behavior.

- [x] Subscription requests during reassignment see either the old or new binding. They never see a transient unassigned state for a successful move.
- [x] A failed move preserves the previous binding and leaves IP and port ownership consistent.
- [x] A connected client follows a successful cross-host move without another login or a manual reconnect.

## CC-06 [P2] Recheck the password revision before issuing a device token

`Store.login` verifies the password outside the write transaction. The transaction then reloads the user and issues a token without checking whether the verified password hash is still current. A concurrent password reset with device revocation can complete in that interval. [Login transaction](../controlplane/store.py#L535) · [Password reset](../controlplane/store.py#L407)

Keep the expensive password verification outside the write lock if practical. Inside the token-issuance transaction, confirm that the verified credential revision still matches the current account before creating or rotating a device token.

- [x] A stale password verification result is rejected after a password reset commits.
- [x] Reset with device revocation still invalidates earlier device sessions. The new password can create a new authorized session.
- [x] Ordinary successful login and same-device token rotation retain their behavior.

## CC-07 [P2] Ignore responses from superseded client sessions

Desktop refresh reads a session, waits for the control plane, and then writes cached exit details or clears files. Config polling also writes or removes files using the session captured before the request. A response arriving after logout and a new login can affect the replacement session. [Desktop refresh](../client/desktop/src-tauri/src/main.rs#L106) · [Config polling](../client/core/src/sync.rs#L19)

Associate each request with a session identity or generation. Check that it is still current when committing cached details, configuration, ETags, or session changes. Apply the check and the state mutation together so a login cannot replace the session between them.

- [x] A delayed `401`, `409`, or successful config response from a previous session leaves the replacement session and its configuration intact.
- [x] A valid `401` or `409` for the active session still applies the intended sign-out or disconnect behavior.
- [x] Desktop status continues to show the active session's cached exit details across local refreshes.

## CC-08 [P2] Apply per-source login limits correctly behind a reverse proxy

The login limiter uses the TCP peer address. In the documented reverse-proxy deployment, that address can be the proxy for every request. Users behind the proxy then share a single address counter and can be locked out by another user's failed logins. [Login limiter key](../controlplane/server.py#L245) · [Deployment notes](../controlplane/README.md#L193)

Enforce the per-source limit at the ingress proxy, or derive the client address only from explicitly trusted proxies. Keep per-account rate limiting. For direct requests, use the actual transport peer address and disregard untrusted forwarding headers.

- [x] Distinct clients behind a trusted proxy maintain separate address counters.
- [x] A direct request cannot change its rate-limit identity with a forwarding header.
- [x] Existing per-user and direct-client limits still work through the chosen deployment.

## Verification and handoff

The review baseline passed 76 Python tests, both Docker end-to-end suites, and Rust workspace compilation and Clippy. The Rust workspace had no automated unit tests at that point. Docker verification used an isolated copy with a different fixture WAN subnet because the running demo owned the default subnet.

Run the existing suites after the fixes and add focused regression coverage for the acceptance criteria above. The Docker control-plane suite exercises the Linux CLI and TUN. The macOS and Windows desktop elevation and TUN paths still require platform-specific verification. Record the commands, results, and any platform checks that remain open when closing this issue.

## Resolution (2026-11-22)

| Finding | Change | Regression coverage |
| --- | --- | --- |
| CC-01 | New `client/core/src/runtime.rs`. The supervisor reads the client config as a regular file of at most 1 MiB (links refused), extracts a `TunnelSpec`, validates every field, renders the sing-box config itself and accepts the client file only if it equals that rendering. The rendering (with the supervisor's own cache path), working dir, log and status live in a root-owned directory: `/Library/Application Support/CCProxy` on macOS, `/var/lib/ccproxy` on Linux, `%ProgramData%\CCProxy` on Windows with its ACL reset. The directory and its parent must be root-owned and not group/world-writable. `sing-box check`, start, reload and restart all use that protected copy. The user directory is only read (the config) or stat'ed (stop, heartbeat). The elevation launcher no longer redirects output into the user directory. The desktop app reads status from the protected directory and ignores status from before the last connect. | `core/tests/runtime_boundary.rs`: gen.py fixtures round-trip exactly; tampered configs refused (log.output, cache path, extra in/outbounds, route changes, TLS insecure, malformed uuid/server/key/fingerprint/DNS, path-like domains, control characters); links and oversized files refused; the protected dir refuses links and non-root ownership. `core/tests/supervisor_boundary.rs`: sing-box only runs the protected copy (0600); a tampered config is refused while running with no reload; a legitimate change reloads; stop and stale heartbeat stop it; a tampered config never starts. The fixtures pin the gen.py contract (`core/tests/fixtures/regen.py`). |
| CC-02 | `agent.py` tracks `installed` (written) separately from `applied` (confirmed). `--run`: sing-box must still be alive 1.5 s after start/SIGHUP. `--reload-cmd`: the command and `--status-cmd` must succeed. A failed reload is retried every cycle, also after a 304 for the written candidate. The heartbeat reports the applied version plus `apply_error`, which the console shows as 新配置未生效. | `tests/test_agent_review.py`: transient failure keeps the old ETag visible, retries after 304, advances only on success (`--reload-cmd` and `--run`); `--status-cmd` failure counts; an invalid candidate keeps the working config; the settle window still coalesces into one reload. Mutation check: the pre-fix behaviour fails both reload tests. |
| CC-03 | Probe rounds run on their own thread, never overlapping, with 16 workers. Each result enters a bounded buffer (4000) as it completes; every heartbeat sends up to 2000 of them, and a failed report keeps them. | `tests/test_agent_review.py`: during a hanging 200-IP round the heartbeat returns immediately, a config change is applied, no second round starts, completed results are reported before the round ends, all 200 arrive afterwards, and the buffer is bounded. |
| CC-04 | Exit route rules: sniff → resolve (IPv4 only, now unconditional) → reject `::/0` → private/blocked filters → per-user routing → final deny. | `tests/test_review_cp.py` (rule order, present with private targets allowed, pinned `sing-box check`). Live in the control-plane e2e: an IPv6 destination sent through a device's tunnel was closed by the exit without any outbound dial. Both e2e suites still pass, including private-address and unassigned-device checks. |
| CC-05 | `Store.reassign` validates the target and moves IP, port and old-IP cooldown in one transaction. It keeps the entry port on a same-host move, and an automatic pick avoids the current IP. Exposed as `POST /admin/users/{user}/reassign`, `cpctl reassign`, and the console's 更换出口 button. `release` is unchanged. | `tests/test_review_cp.py`: a concurrent subscriber never sees 409 during a cross-host move; failed moves change nothing (bindings, ports, version, IP states); API plus ETag poll follows the move. Control-plane e2e: the running Linux client follows `cpctl reassign` to the other host without exiting. |
| CC-06 | `Store.login` keeps PBKDF2 outside the lock and, inside the issuing transaction, requires the stored hash to equal the one verified. | `tests/test_review_cp.py`: a reset with device revocation committed between verification and issuing wins; the new password works; ordinary login and same-device rotation are unchanged. Mutation check: removing the recheck fails the test. |
| CC-07 | Sessions carry an id that is new on every sign-in. `sync_once` and the desktop exit-info refresh apply a reply only if that id is still current, checked and applied under one process-wide session lock (the same lock sign-in and sign-out take). The desktop cache is keyed by session id. | `core/tests/session_generation.rs`: delayed 401 / 409 / 200 for a replaced session leave the new session, config and ETag intact; 401 and 409 for the current session still sign out or disconnect. Mutation check: removing the check fails all three late-reply tests. |
| CC-08 | `serve --trusted-proxy CIDR` (repeatable, or `CP_TRUSTED_PROXIES`). `X-Forwarded-For` is used only when the TCP peer is a trusted proxy, taking the rightmost non-proxy hop; otherwise the peer address. The same client address feeds the login limiters, audit log and admin sessions. `X-Forwarded-Proto` (Secure cookie) is also believed only from trusted proxies. Per-account limits are unchanged. | `tests/test_review_cp.py` and the updated `tests/test_console.py`: clients behind a trusted proxy have separate counters; a spoofed leftmost hop is ignored; direct requests cannot change identity with headers; forwarded-proto is ignored without trust; the per-user limit still applies. Mutation check: trusting every peer fails the direct-request test. |

Found and fixed while doing this:

- The supervisor captured the config's mtime only after the 1.5 s DNS settle, so a change written in that window went unnoticed. It now records the mtime of the version it loads.
- `--trusted-proxy` was missing from `server.py serve` in the first cut, because an unasserted text edit did not apply. The unit tests did not cover `main()`. The control-plane e2e caught it.

### Commands and results

```text
python3 -m unittest discover -s controlplane/tests      114 tests OK (was 76 at the review baseline)
cd client && cargo test --workspace                     17 tests OK (the review baseline had none)
cd client && cargo clippy --workspace --all-targets -- -D warnings      clean
controlplane/test/run-e2e.sh                            CP E2E PASS (two exits, Linux ccproxy TUN client as root
                                                        with the protected runtime in /var/lib/ccproxy, atomic reassign)
egress/test/run-e2e.sh                                  E2E PASS
macOS app bundle rebuilt (Apple silicon); bundled ccproxy contains the protected-runtime path
```

### macOS check (2026-11-22, Apple silicon, local demo)

The rebuilt app was connected by the user. The supervisor created `/Library/Application Support/CCProxy` as `root:admin` 755, holding `config.json` (0600), `tunnel.log` (0600), `status.json` and `work/cache.db`. sing-box ran as root with `-c /Library/Application Support/CCProxy/config.json`. As the signed-in user, appending to that config and creating a file in the directory both failed with permission denied. The status showed `running`. `/etc/resolver/echo.example.com` pointed at the TUN DNS; `echo.example.com` resolved to a fake IP and returned the exit IP `10.99.0.3`; `api.ipify.org` still showed the local public IP and `example.com` loaded directly.

### Still open (platform checks)


- **Windows**: the ACL reset with `icacls` on `%ProgramData%\CCProxy`, the UAC launch, and TUN. Not built or run.
- **Linux desktop**: the pkexec launch. The supervisor path as root is covered by the e2e.
- **Residual risk outside this issue**: the app bundle, including the `ccproxy` and `sing-box` binaries that get elevated, is writable by whoever installed it. Malware running as the same user could replace them before the next connect. Fixing that needs a root-owned privileged helper (macOS SMJobBless, a Windows service, a Linux system unit) instead of per-connect elevation.
