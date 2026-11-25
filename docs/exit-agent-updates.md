# Managed automatic updates for exit Agents (issue #67)

An exit host installed with the current installer moves to an approved Agent release by itself. The operator
publishes a signed release, picks a pilot host or a cohort, watches each host's running version and outcome,
widens or pauses the rollout, and retries hosts that failed. A candidate that does not report healthy is
rolled back to the previous binary automatically.

Only the Agent binary changes. The enrollment token, `install.conf`, the sing-box and frpc binaries and their
configuration, the services, and the IP and port assignments stay as they are.

## Pieces

| Piece | Where | Role |
| --- | --- | --- |
| Release record | `egress/agent/release` | `release.json`: version, **sequence**, commit, and every platform's file, size and SHA-256. `release.json.sig`: Ed25519 signature over the exact bytes. |
| Release tool | `egress/agent/cmd/agent-release` | `keygen`, `record`, `sign`, `verify`. |
| Trusted keys | `egress/agent/release_keys.txt` | Public keys compiled into the Agent. With no key, updates are disabled (`update.state = disabled`). |
| Release workflow | `.github/workflows/exit-agent.yml` | The operator's publish step. It builds reproducibly, writes the record with `sequence = run number`, and signs with the secret `AGENT_RELEASE_SIGNING_KEY`. It then checks the signature against `release_keys.txt`. |
| Release store | control plane, `CP_AGENT_RELEASES/<version>/` | Unpacked workflow artifacts, one directory per release. The control plane serves them but cannot forge them. |
| Rollout | control plane, `agent_update.go` | One rollout: version, target hosts (a list or all), paused flag, and a rollout id. Per-host status comes from heartbeats. |
| Updater | Agent, `egress/agent/update.go` | Check, verify, download, self-test, activate, confirm, roll back. |

### Why the signature and the sequence

The control plane is reachable from the internet and holds every host's token. A host must not run a binary
merely because the control plane offered it. The Agent therefore accepts only a record signed by a key compiled
into the binary it already runs.

Agent versions are source hashes (`agent-<tree>`), so they cannot be ordered. The release sequence orders them.
It is the exit-agent workflow's run number, so a later publication is always newer. An Agent never moves to a
sequence lower than or equal to the release it runs. A replayed old record is refused, and so is a downgrade.
To go back to older code, publish it again so it gets a new sequence; reverting the commit and running the
workflow does this.

## Agent behaviour

Every `--update-interval` seconds (default 120), the Agent calls `GET /agent/update`. It answers 204 when there
is no rollout, the rollout is paused, or the host is not targeted. Otherwise it returns
`{"rollout_id", "release", "signature"}`. The Agent then:

1. Verifies the signature with its compiled-in keys and parses the record strictly: unknown fields, unknown
   platforms, bad file names, digests or sizes, and `-dirty` versions are all refused. A refused record is
   reported as `rejected` and not retried for that rollout id.
2. Requires the record's sequence to be higher than the running release's sequence. If the record is the
   version already running, it only records the sequence and reports `current`.
3. Requires a build for its own platform. If there is none, the release is incompatible (`rejected`).
4. Downloads `GET /agent/update/<version>/<platform>` into `<exe>.download`. It refuses more bytes than the
   record lists, checks size and SHA-256, and renames the file to `<exe>.candidate`. A tampered, truncated or
   interrupted download is deleted and reported as `failed`; the next check retries. A staged candidate whose
   digest still matches is reused without downloading again.
5. Self-tests the candidate: `<candidate> version` must print the signed version, and `<candidate> check-args
   <this agent's arguments>` must accept the host's command line. A candidate that does not run on the host,
   reports another version, or rejects a flag is incompatible (`rejected`).
6. Asks `GET /agent/update` again. If the rollout was paused or changed during the download, the candidate
   stays staged and is not activated.
7. Activates it:
   - Records the activation, with a health baseline of whether sing-box was confirmed and running and whether
     XTCP was applied, in `<state-dir>/update-state.json`.
   - Copies the running binary to `<exe>.previous`.
   - Moves the candidate to `<exe>` with a rename. On Windows the running file is first renamed to
     `<exe>.replaced`.
   - Exits with status 75. The service manager starts the new binary: systemd through `Restart=always`, launchd
     through `KeepAlive`. On Windows, a detached `--update-restart-cmd` ends and starts the `CCProxyExitAgent`
     task.

The new binary starts in the `confirming` phase. It confirms itself after **two consecutive healthy cycles**:
the control plane accepted the heartbeat, and sing-box (and frpc on XTCP hosts) is at least as healthy as in the
baseline. It is rolled back when either of these happens:

- It is not healthy within `--update-health-timeout` (default 600 s).
- It is started more than 3 times without confirming, because it crashes or exits at start. This is counted
  at the start of `run`, before anything that can fail.

Rollback copies `<exe>.previous` back to `<exe>`, records `rolled_back` with the reason, and exits with status
75. The previous binary starts and reports the outcome. A rolled-back target is not retried for the same rollout
id. The operator retries by setting the rollout again, which creates a new id.

### No traffic interruption on Linux and macOS

Before this change, every Agent start reloaded sing-box with a fresh confirmation secret, which drops open
connections. Now the Agent records the confirmed configuration's ETag, secret and marker in
`confirmed-state.json`. A restarted Agent adopts the running sing-box without a reload, but only if all of these
hold:

- `--config` is byte for byte the confirmed copy.
- sing-box proves on its loopback API that it serves that marker.
- sing-box runs as its own service (`--reload-cmd`).

XTCP state was already persisted, so frpc is neither restarted nor reloaded. An update or rollback therefore
touches neither sing-box nor frpc.

### Interruptions

| What happens | Result |
| --- | --- |
| Download fails or is cut off | Partial file removed. The current release keeps running and the next check resumes from a clean start. |
| Power loss after the activation is recorded but before the swap | The old binary starts, sees it is still the previous version, and records `failed` ("activation interrupted"). It retries, up to 3 times per rollout. |
| Power loss after the swap | The candidate starts and confirms or rolls back as usual. |
| Installer rerun or manual replacement during an update | The binary is not the target or the previous version, so the state starts over from it (`installedExternally`). |

## Contract with the control plane (and #66 / #68)

The heartbeat (`POST /agent/report`) gains two optional fields. Older control planes ignore them, and older
Agents simply omit them.

```json
"agent_version": "agent-6f21ad6f0bcf",
"update": {
  "state": "disabled|idle|current|downloading|confirming|updated|rolled_back|rejected|failed",
  "target_version": "agent-...", "target_sequence": 42, "rollout_id": 7,
  "running_sequence": 41, "previous_version": "agent-...", "error": "...", "at": 1795576048
}
```

`agent_version` is the running binary's `main.version`, which `build.sh` stamps. This is the field #66 persists
and shows in the console as **Agent version**. The control plane in this change stores it, with the update
outcome, in `agent_update_status` for the rollout view. When #66 lands, its per-host column and this table
should read from the same heartbeat field, so one of the two can be dropped. The desktop updater (#68) does not
use these routes. It shares only the idea of a signed record with an explicit sequence, and can reuse
`egress/agent/release` if that helps.

Agent routes (host token):

- `GET /agent/update` returns 204, or `{"rollout_id", "release", "signature"}`.
- `GET /agent/update/{version}/{platform}` returns a published binary. It is served only while it matches
  `release.json`.

Admin routes (audited): `GET /admin/agent-releases`, `GET /admin/agent-rollout`, `PUT /admin/agent-rollout`,
`POST /admin/agent-rollout/pause`, `POST /admin/agent-rollout/resume`, `DELETE /admin/agent-rollout`. The same
actions are in `controlplane/cpctl.py` (`agent-releases`, `agent-rollout`, `agent-rollout-set`,
`agent-rollout-pause`, `agent-rollout-resume`, `agent-rollout-clear`).

`GET /admin/agent-rollout` gives each host an `outcome` for the current rollout:

| Outcome | Meaning |
| --- | --- |
| `not_targeted` | Keeps its release. |
| `waiting` | Targeted but not started: before the next check, or the rollout is paused. |
| `in_progress` | Downloading or confirming. |
| `on_target` | Running the rollout's version. |
| `failed` | Rolled back, refused or failed for this rollout id. See `error`. |
| `upgrade_needed` | The Agent has no updater. Run the installer once. |
| `disabled` | The updater is off (no key in the build, or `--update off`). See `error`. |
| `unknown` | No heartbeat yet. |

## Operator runbook

### One-time setup (project owner)

1. Generate the release key on a trusted machine, and keep the private key offline:

   ```bash
   cd egress/agent && go run ./cmd/agent-release keygen /secure/agent-release.key
   ```

2. Add the printed `ed25519:...` line to `egress/agent/release_keys.txt`. Commit it through a normal PR.
3. Store the private key (the file's single line) as the GitHub Actions secret `AGENT_RELEASE_SIGNING_KEY`. A
   protected environment with required reviewers is the better home for it.
4. Give the control plane a release store, mounted read-only, for example:
   `-v /srv/ccproxy/agent-releases:/agent-releases:ro -e CP_AGENT_RELEASES=/agent-releases`.
5. Bootstrap each existing host once, because Agents from before this change have no updater:
   - Build and serve an Agent that contains the key: run the workflow, then point `CP_AGENT_DIST` at its
     artifact.
   - Rerun the host's install command from the console. It keeps the token if you press Enter at the prompt,
     and it keeps the configuration.
   - `cpctl.py agent-rollout` then shows the host as something other than `upgrade_needed`.

### Publish a release

1. Merge to `main`, then run **Actions → exit-agent → Run workflow**. The summary names the version and the
   release sequence (the run number). If the signing secret is missing, the run warns and the artifact is for
   installers only.
2. Download the `aifree-exit-agent` artifact. Unpack it to `CP_AGENT_RELEASES/<version>/` on the control plane
   (the directory name must equal `VERSION`).
3. Check it there:

   ```bash
   go run ./cmd/agent-release verify -dist <dir> -keys release_keys.txt
   ```

   ```bash
   cpctl.py agent-releases
   ```

### Roll it out

```bash
cpctl.py agent-rollout-set agent-<new> macmini-sg-208     # pilot: one host
cpctl.py agent-rollout                                    # watch: outcome, running version, state, error
```

Within one check interval (120 s by default), plus about 15 s for confirmation, the pilot shows `on_target` and
`updated`, and its heartbeat reports the new `agent_version`. Check the host's traffic and XTCP ports in the
console. Then widen the rollout:

```bash
cpctl.py agent-rollout-set agent-<new> host-a host-b host-c   # a cohort
cpctl.py agent-rollout-set agent-<new> --all                  # everyone
```

The rollout commands:

| Command | Effect |
| --- | --- |
| `cpctl.py agent-rollout-pause` | No further host starts the update. A host already confirming finishes or rolls back. |
| `cpctl.py agent-rollout-resume` | Continues the paused rollout. |
| `cpctl.py agent-rollout-set <same args>` | Retries hosts that failed: it creates a new rollout id. Read their `error` first. |
| `cpctl.py agent-rollout-clear` | Stops the rollout. Every host keeps what it runs; nothing is downgraded. |

After the whole fleet runs the new release, point `CP_AGENT_DIST` at the same directory so new installs get it
too. A release directory is also a valid installer dist.

### Undo a bad release

- **Not healthy:** the Agent rolls itself back and reports `failed` / `rolled_back`. Pause the rollout and fix
  the release.
- **Healthy, but you want the old code back:** revert on `main` and publish again, which gives a new, higher
  sequence. Then roll that release out.
- **Emergency on one host**, if you have shell access:
  - Linux:

    ```bash
    sudo cp /opt/ccproxy-exit/bin/ccproxy-exit-agent.previous /opt/ccproxy-exit/bin/ccproxy-exit-agent.new && sudo mv /opt/ccproxy-exit/bin/ccproxy-exit-agent.new /opt/ccproxy-exit/bin/ccproxy-exit-agent && sudo systemctl restart ccproxy-exit-agent
    ```

  - macOS: the same paths with `launchctl kickstart -k system/com.ccproxy.exit.agent`.
  - Or rerun the install command, which installs `CP_AGENT_DIST`.

  Then exclude the host from the rollout, or clear the rollout.

### Rotate the release key

1. Add the new public key to `release_keys.txt`, keep the old one, and publish that build, signed with the
   **old** key.
2. Once every host runs it, switch the secret to the new key.
3. Remove the old public key in a later release.

## Platform coverage

| Platform | Service restart | Validated here | Gaps |
| --- | --- | --- | --- |
| Linux (systemd), amd64/arm64 | exit 75, then `Restart=always` | `controlplane/test/xtcp/run-e2e.sh`: the real installer, systemd, sing-box 1.14.4 and frp 0.72.0. See the evidence list below. | Validated in a Debian 12 container (arm64), not on a bare-metal or VM host. |
| macOS (launchd), arm64/amd64 | exit 75, then `KeepAlive` | `TestUpdateWithRealBinaries` on darwin/arm64 runs compiled Agents under a restart-on-exit supervisor with sing-box as a separate process: v1 → v2, then v3 rolled back. | Not run under a real launchd daemon on a Mac host (for example macmini-sg-208). Do that as the pilot. |
| Windows (scheduled task), amd64/arm64 | `--update-restart-cmd` (PowerShell: end and start the task) | Cross-compiled and vetted only. | **Not run on Windows.** Untested: renaming the running `.exe`, the detached restart helper surviving the task's end, and the task restarting a crashed candidate (Task Scheduler's restart-on-failure may not count a non-zero exit). sing-box runs under the Agent there, so every Agent update restarts sing-box: a few seconds without service. Pilot one Windows host and watch it before including others. |

Evidence produced for this change (local, 2026-11-25, macOS arm64 with Docker Desktop):

- `go test -race ./...` in `egress/agent`, including the updater unit tests and `TestUpdateWithRealBinaries`.
- `go vet` for all six targets.
- The control-plane Go suite with `TEST_DATABASE_URL` (PostgreSQL 14), including
  `TestAgentRolloutTargetsPausesAndReports`.
- The release tool rehearsal: `build.sh --verify`, then `record`, `sign` and `verify`. Verification fails on a
  tampered binary and with the repository's empty key list.
- `controlplane/test/xtcp/run-e2e.sh` with the update phase. It covers:
  - a host outside the rollout, and a paused rollout, both keeping the release;
  - a tampered release binary being refused;
  - the automatic v1 → v2 update through systemd, with continuous Direct and XTCP probes for two users on two
    ports;
  - unchanged sing-box and frpc MainPIDs;
  - the v3 rollback rehearsal;
  - the reboot and uninstall checks.

## Security notes

- The private key never reaches the control plane or the hosts. A compromised control plane can withhold
  updates, or offer an older *signed* release to a host whose running sequence is unknown (a host installed by
  the installer, before its first update). It cannot make a host run unsigned code.
- Every update request carries the host token and never follows redirects, like all Agent requests. The binary
  is written by root (or SYSTEM) next to the installed binary, so the installer's trusted-path rules still hold.
- `AGENT_EXTRA_RELEASE_KEYS` (`build.sh`) and `-X main.extraReleaseKeys` exist for test builds only, such as the
  e2e. A build for real hosts must not set them; `build.sh` prints a warning when it does.
