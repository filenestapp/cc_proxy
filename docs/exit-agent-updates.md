# Managed exit Agent updates

This document describes the current managed-update design for the Go exit Agent. An operator
publishes a signed release, adds an approved version to a rollout, and starts with a pilot host.
The Agent downloads and validates its candidate in the background. The stable launcher selects the
candidate only after the Agent records an activation, and it restores the prior confirmed release
when the candidate cannot confirm healthy.

The update path changes only the Agent executable. It preserves the host token, install settings,
sing-box and frpc executables, their configuration, egress IP assignments, and user port mappings.

## Release and rollout model

An exit-agent release is the `dist/` directory produced by `egress/agent/build.sh`, plus:

- `release.json`, containing the semantic Agent version, monotonic workflow sequence, source commit, and
  every supported binary's filename, size, and SHA-256.
- `release.json.sig`, an Ed25519 signature over the exact `release.json` bytes.

Published Agent versions use `vMAJOR.MINOR.PATCH`, such as `v0.1.0`. The version is stored in
`egress/agent/RELEASE_VERSION` and its `exit-agent/<version>` Git tag must point at the released source commit.
Treat a published version's tag as immutable. Existing `agent-<hash>` versions remain supported for installed
nodes and historical signed releases. The exit-agent workflow uses its run number as the sequence.
An Agent accepts a target only when
its signed sequence is greater than the sequence of its current release.

The public keys in `egress/agent/release_keys.txt` are compiled into the Agent. The control plane
can store and serve a signed release, yet it cannot make a host run an unsigned binary or a binary
whose digest differs from the release record.

The release workflow is deliberately manual on `main`. It builds the six supported Agent targets, writes the
release record, and verifies its signature using the public keys compiled into the Agent. It requires
`AGENT_RELEASE_SIGNING_KEY` from the protected `release` environment. Unsigned artifacts can only be used by
installers.

## Control-plane contract

Set `CP_AGENT_RELEASES` to the directory that contains one published subdirectory per release:

```text
CP_AGENT_RELEASES/
  <version>/
    VERSION
    SHA256SUMS
    ccproxy-exit-agent-<platform>[.exe]
    release.json
    release.json.sig
```

The control plane validates the published files before listing or serving them. The Agent uses its
host token for these routes:

- `GET /agent/update` returns `204` when the host has no active target, is outside the rollout, or
  the rollout is paused. Otherwise it returns the rollout id and the signed target record.
- `GET /agent/release/{version}` returns a published signed record for the version already running.
  A newly installed Agent uses this to establish the current release sequence. The record's binary
  digest must match its own executable before the Agent can accept a later target.
- `GET /agent/update/{version}/{platform}` returns the target binary only after the control plane
  rechecks its size and SHA-256 against `release.json`.

The first condition is important. A host with the new launcher must also have its currently
installed signed release published in `CP_AGENT_RELEASES`. Otherwise it reports that its running
release is not established and will not advance to a target.

Administrators use these existing commands:

```bash
cpctl.py agent-releases
cpctl.py agent-rollout
cpctl.py agent-rollout-set v<version> macmini-sg-208
cpctl.py agent-rollout-set v<version> --all
cpctl.py agent-rollout-pause
cpctl.py agent-rollout-resume
cpctl.py agent-rollout-clear
```

Repeating `agent-rollout-set` creates a new rollout id and retries a host that previously rejected
or rolled back that version. Read the host error before retrying.

## Host layout and lifecycle

The installer places a stable launcher at:

```text
/opt/ccproxy-exit/bin/ccproxy-exit-agent
```

The service always starts that path. On Linux and macOS, the launcher uses `exec` to run the chosen
release. On Windows, it supervises the selected release as a child, using a kill-on-close job and
its own restart loop. This keeps update recovery independent of a scheduler interpreting a nonzero
exit as a restart.

Candidates are never copied over the stable launcher. The Agent stages each verified candidate at:

```text
/opt/ccproxy-exit/bin/releases/<version>/ccproxy-exit-agent-<platform>[.exe]
```

The persistent selection and health state is:

```text
/var/lib/ccproxy-exit/agent/update-state.json
```

The Agent checks its rollout at `--update-interval`, which defaults to 120 seconds. It verifies the
record and release sequence, downloads the platform candidate with a byte limit, validates its
size and SHA-256, and runs `version` plus `check-args` before activation. Download and self-test
run in the background while heartbeat, configuration sync, sing-box, and XTCP work continue.

Activation records the candidate and exits with status 75. The launcher counts candidate starts
and runs it in the confirming phase. The candidate confirms after two consecutive healthy cycles
within `--update-health-timeout`, which defaults to 600 seconds. Health includes an accepted
heartbeat and at least the sing-box and XTCP health recorded at activation. A missing candidate,
failed startup, too many starts, or a missed health deadline restores the previous release and
records the reason. A rollout target that is rejected or rolled back is blocked until the operator
creates a new rollout id.

An installer upgrade is also a recovery path. When the stable launcher itself changes, it resets
the update selection to the installed launcher and removes staged releases. The operator then
publishes the matching signed installed release before beginning a managed rollout again.

## Publishing and pilot procedure

1. Generate a release key on an owner-controlled machine and add its public key to
   `egress/agent/release_keys.txt` before building the Agent that will trust it.
2. Store the private key as `AGENT_RELEASE_SIGNING_KEY` in the GitHub `release` environment restricted to `main`.
3. Bump `egress/agent/RELEASE_VERSION`, merge it, and create the matching `exit-agent/<version>` tag on that commit.
   For example, tag the release commit with `git tag exit-agent/v0.1.0 <commit>`, then push that tag and
   run **Actions → exit-agent → Run workflow** on `main` at the same commit.
4. Download the `aifree-exit-agent` artifact and place its complete signed contents in
   `CP_AGENT_RELEASES/<version>/`.
5. Verify the copied artifact before changing any rollout:

   ```bash
   cd egress/agent
   go run ./cmd/agent-release verify -dist <published-release-directory> -keys release_keys.txt
   cpctl.py agent-releases
   ```

6. Ensure the installed release is also published, then create a one-host pilot:

   ```bash
   cpctl.py agent-rollout-set v<new-version> macmini-sg-208
   cpctl.py agent-rollout
   ```

7. Watch the pilot until the rollout view reports the target as `on_target`, shows the expected
   running Agent version, and has no update error. Exercise its assigned traffic and, for an XTCP
   host, every active entry port. Pause the rollout before investigation if the host rolls back.
8. Widen only after the pilot is accepted. `agent-rollout-clear` stops future targeting and never
   downgrades a host.

For a healthy release that must be undone, publish the desired older source as a new signed release
with a higher sequence and roll out that new version. Do not attempt to replay an earlier sequence.

## Security and recovery properties

- The private release key never reaches the control plane or exit hosts.
- The Agent checks the signature, target platform, size, SHA-256, signed sequence, executable
  version, and its own command-line compatibility before activation.
- An interrupted or damaged staged candidate does not replace the stable launcher. It is retried
  only through normal signed rollout handling.
- The launcher stores its choice before it runs a candidate, so a candidate that exits before its
  own update logic starts can still be rolled back on the next launcher start.
- A control-plane compromise can withhold an update. It cannot make an established host run an
  unsigned release or silently downgrade the signed sequence.

## macOS acceptance scope

This rollout currently needs macOS acceptance before it is presented as ready for fleet use. The
acceptance host must use the launchd service installed at
`system/com.ccproxy.exit.agent`, a signed published installed release, and a separately signed
candidate release. The acceptance run must demonstrate all of the following:

1. The stable launcher stages and activates the candidate through launchd without replacing its own
   installed path.
2. The candidate reaches the required healthy cycles and reports the target Agent version and
   update outcome through the control plane.
3. A deliberately unhealthy candidate is recovered by the launcher to the prior release, with the
   recorded reason visible in the rollout status.
4. Existing sing-box traffic continues across a successful update and rollback. An XTCP host also
   keeps its active frpc mapping and every assigned port reachable.
5. Reboot recovery starts the stable launcher and the selected release without an interactive macOS
   login.

The final test evidence and any remaining platform gaps belong in the rollout or pull-request
record. This document intentionally does not claim that those acceptance steps have completed.
