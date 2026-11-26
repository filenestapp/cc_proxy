#!/usr/bin/env bash
# Control-plane e2e (v2): two exit hosts, users with passwords bound to an exit IP and an entry port.
# Everything goes through the admin API and the client sign-in API; nothing is rendered or reloaded by hand.
#   phase 1  provisioning: hosts, IPs, users (exclusive, auto-assigned, shared, unassigned, on the second host);
#            devices sign in with passwords; one device is revoked after it got its config
#   phase 2  a burst of admin changes: release, revoke, assign an unassigned user on the other host. Agents
#            reload once per host; the waiting client picks up its new config by itself
#   phase 3  health data: both agents in sync, entry latency per host, per-IP probes (one IP refused)
#   phase 4  alerts: refused IP and dead entry fire; ban resolves; stopping one host's agent fires agent_stale
# KEEP=1 leaves the containers running (dashboard on http://127.0.0.1:18443/dashboard).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
CP="http://127.0.0.1:18443"
rnd() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }
export CP_ADMIN_TOKEN="admin-$(rnd)" CP_PROBE_TOKEN="probe-$(rnd)" HK_TOKEN="" JP_TOKEN=""
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }
cpctl() { CP_URL="$CP" python3 "$HERE/../cpctl.py" "$@"; }
json_field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

cleanup() {
  if [[ "${KEEP:-0}" != 1 ]]; then compose --profile agents --profile clients --profile desktop down -v --remove-orphans >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

rm -rf "$OUT" && mkdir -p "$OUT/creds"
cat > "$OUT/settings.json" <<'JSON'
{
  "client_policy": {
    "domain_suffix": ["target.test"], "direct_dns": "127.0.0.11",
    "domain_groups": {
      "claude": {"enabled": true, "domain_suffix": ["claude-route.test"]},
      "openai": {"enabled": true, "domain_suffix": ["openai-route.test"]},
      "gemini": {"enabled": true, "domain": ["gemini-route.test"]}
    }
  },
  "cooldown_seconds": 3600,
  "monitor": {"egress_targets": ["http://target.test:8080/strict"],
              "entries": [{"name": "backup", "host": "10.88.0.5", "port": 9}]},
  "alerts": {"webhooks": [{"url": "http://10.88.0.50:8080/hook"}], "consecutive_failures": 2,
             "agent_stale_seconds": 12, "out_of_sync_seconds": 60, "eval_interval": 2}
}
JSON

echo "== start control plane"
compose --profile agents --profile clients --profile desktop down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --build --wait cp echo decoy sink probe 2>&1 | tail -n 1
compose --profile desktop build desktop 2>&1 | tail -n 1

status=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; status=1; fi; }

echo "== phase 1: hosts, IPs, users, sign-in"
# The test "internet" is a private subnet, so allow private targets but still refuse the decoy (10.99.0.20).
block=(--allow-private --block-cidr 10.99.0.20/32 --block-cidr 169.254.169.254/32)
HK_TOKEN=$(cpctl host-add hk-1 10.88.0.2 decoy.test --handshake 10.99.0.20 --ports 20000-20099 "${block[@]}" | json_field '["agent_token"]')
JP_TOKEN=$(cpctl host-add jp-1 10.88.0.3 decoy.test --handshake 10.99.0.20 --ports 30000-30099 "${block[@]}" | json_field '["agent_token"]')
export HK_TOKEN JP_TOKEN
cpctl ip-add hk-1 10.99.0.3 10.99.0.4 10.99.0.5 10.99.0.6 >/dev/null
cpctl ip-add jp-1 10.99.0.13 10.99.0.14 >/dev/null
compose --profile agents up -d egress-hk egress-jp 2>&1 | tail -n 1

for u in alice bob erin frank gina; do cpctl user-add "$u" --exclusive --password "pw-$u-0123" >/dev/null; done
for u in carol dave; do cpctl user-add "$u" --password "pw-$u-0123" --shared >/dev/null; done
cpctl assign alice 10.99.0.3 >/dev/null
cpctl assign bob --host hk-1 >/dev/null            # auto: lowest free IP and port on hk-1
cpctl assign carol 10.99.0.5 >/dev/null
cpctl assign dave 10.99.0.5 >/dev/null
cpctl assign frank 10.99.0.6 --port 20050 >/dev/null
cpctl assign gina --host jp-1 >/dev/null
cpctl hosts
cpctl users

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CP/v1/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"wrong-password","device":"x"}')
check "wrong password is rejected (401)" '[[ $code == 401 ]]'

python3 - "$OUT/creds/devices.json" <<'PY'
import json, sys
devs = [("alice-mac", "alice"), ("alice-win", "alice"), ("bob-mac", "bob"), ("carol-mac", "carol"),
        ("dave-mac", "dave"), ("erin-mac", "erin"), ("frank-old", "frank"), ("frank-new", "frank"), ("gina-mac", "gina")]
json.dump([{"device": d, "user": u, "password": "pw-%s-0123" % u, "port": 2081 + i} for i, (d, u) in enumerate(devs)],
          open(sys.argv[1], "w"), indent=2)
PY
compose --profile clients up -d --wait clients 2>&1 | tail -n 1
cpctl revoke frank frank-old >/dev/null

# Each running client must point at its user's host and entry port.
users_json=$(python3 -c "
import json, os, urllib.request
r = urllib.request.Request('$CP/admin/users', headers={'Authorization': 'Bearer ' + os.environ['CP_ADMIN_TOKEN']})
print(json.dumps(json.load(urllib.request.urlopen(r))))")
compose logs --no-log-prefix clients | python3 -c "
import json, re, sys
users = {u['name']: u for u in json.loads(sys.argv[1])}
lan = {'hk-1': '10.88.0.2', 'jp-1': '10.88.0.3'}
bad = 0
for line in sys.stdin:
    m = re.match(r'config (\S+)\s+-> (\S+):(\d+)$', line.strip())
    if not m: continue
    dev, host, port = m.group(1), m.group(2), int(m.group(3))
    u = users[dev.split('-')[0]]
    ok = (host, port) == (lan[u['host']], u['port'])
    bad += not ok
    print('%s %-10s -> %s:%d (user %s bound to %s:%s)' % ('PASS' if ok else 'FAIL', dev, host, port, u['name'], u['egress_ip'], u['port']))
sys.exit(1 if bad else 0)" "$users_json" || status=1

# The server-config ETag is a hash of its content; wait until each agent's sing-box has confirmed running the
# current one (the agent logs this only after sing-box returned that version's marker, not when it wrote the file).
# (No `grep -q` on `compose logs` anywhere: it exits early, compose dies of SIGPIPE and pipefail fails the check.)
wait_for_agent() {  # SERVICE TOKEN
  local want
  want=$(curl -s -D - -o /dev/null -H "Authorization: Bearer $2" "$CP/agent/server-config" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')
  for _ in $(seq 1 40); do
    compose logs "$1" 2>/dev/null | grep -F "sing-box confirmed running config version $want" >/dev/null && { echo "$1 confirmed version $want"; return 0; }
    sleep 1
  done
  echo "FAIL $1 did not confirm version $want"; compose logs --tail 20 "$1"; return 1
}
reloads() { compose logs "$1" 2>/dev/null | grep -c 'sent SIGHUP' || true; }
wait_for_agent egress-hk "$HK_TOKEN" || status=1
wait_for_agent egress-jp "$JP_TOKEN" || status=1
compose exec -T probe python /app/cp_probe.py initial || status=1

echo "== phase 2: a burst of admin changes"
hk_before=$(reloads egress-hk); jp_before=$(reloads egress-jp)
cpctl release bob >/dev/null
cpctl revoke alice alice-win >/dev/null
cpctl assign erin --host jp-1 >/dev/null
wait_for_agent egress-hk "$HK_TOKEN" || status=1
wait_for_agent egress-jp "$JP_TOKEN" || status=1
hk_r=$(( $(reloads egress-hk) - hk_before )); jp_r=$(( $(reloads egress-jp) - jp_before ))
check "hk-1 reloaded once for two changes (got $hk_r)" '[[ $hk_r -eq 1 ]]'
check "jp-1 reloaded once (got $jp_r)" '[[ $jp_r -eq 1 ]]'
for _ in $(seq 1 15); do compose logs clients | grep 'config erin-mac   -> 10.88.0.3' >/dev/null && break; sleep 1; done
check "erin's waiting client picked up its config by itself" "compose logs clients | grep 'config erin-mac   -> 10.88.0.3' >/dev/null"
compose exec -T probe python /app/cp_probe.py reloaded || status=1
cpctl ips

echo "== phase 3: health data behind the dashboard"
compose exec -T -e CP_ADMIN_TOKEN -e CP_URL=http://cp:8443 probe python /src/controlplane/test/check_topology.py || status=1

echo "== phase 3b: the aifree client (Linux TUN, app mode)"
cpctl ip-add hk-1 10.99.0.7 >/dev/null
cpctl ip-add jp-1 10.99.0.15 >/dev/null
cpctl user-add hana --password pw-hana-0123 >/dev/null
cpctl assign hana 10.99.0.7 >/dev/null
compose --profile desktop up -d desktop 2>&1 | tail -n 1
dx() { compose exec -T desktop "$@"; }
ux() { compose exec -T -u cust -e HOME=/home/cust desktop "$@"; }
stun_hits() {
  compose logs --no-log-prefix echo | awk -v family="${1:-}" -v source="${2:-}" \
    '$1 == "stun" && (!family || $2 == family) && (!source || $4 == source) { ++n } END { print n + 0 }'
}
route_generation() {
  dx python3 -c 'import json; s = json.load(open("/var/lib/ccproxy/status.json")); print(s["route_generation"] if s["state"] == "running" else 0)'
}
tunnel_pid() {
  dx cat /var/lib/ccproxy/status.json | json_field '["pid"]'
}
wait_for_client_reload() {
  local previous=$1 current
  for _ in $(seq 1 20); do
    current=$(route_generation) || return 1
    if [[ "$current" -gt "$previous" ]]; then return 0; fi
    sleep 1
  done
  ux aifree status
  return 1
}
set_stun_policy() {
  local previous
  previous=$(route_generation) || return 1
  curl -fsS -X PUT -H "Authorization: Bearer $CP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"client_policy\":{\"stun\":\"$1\"}}" "$CP/admin/settings" >/dev/null || return 1
  wait_for_client_reload "$previous"
}
ux python3 /app/stun_probe.py disconnected 10.99.0.7 || status=1
ux sh -c 'AIFREE_PASSWORD=pw-hana-0123 aifree login --server http://10.88.0.5:8443 --user hana --device hana-linux' || status=1
ux sh -c 'nohup aifree connect --interval 2 > /tmp/up.log 2>&1 &'
for _ in $(seq 1 20); do ux aifree status 2>/dev/null | grep 'tunnel: running' >/dev/null && break; sleep 1; done
ux aifree status
wait_for_agent egress-hk "$HK_TOKEN" || status=1
dx python3 /app/desktop_probe.py 10.99.0.7 10.88.0.60 --routing-groups || status=1
ipv6_hits=$(stun_hits ipv6)
direct_stun_hits=$(stun_hits ipv4 10.88.0.60)
ux python3 /app/stun_probe.py proxy 10.99.0.7 || status=1
check "the IPv6 STUN responder received no request with proxy" '[[ "$(stun_hits ipv6)" == "$ipv6_hits" ]]'
check "the IPv4 STUN responder received no direct request with proxy" \
  '[[ "$(stun_hits ipv4 10.88.0.60)" == "$direct_stun_hits" ]]'

echo "-- admin moves hana to jp-1 in one step; the client follows without doing anything"
previous_route=$(route_generation)
cpctl reassign hana 10.99.0.15 >/dev/null
wait_for_agent egress-jp "$JP_TOKEN" || status=1
check "client reloaded the reassigned exit" 'wait_for_client_reload "$previous_route"'
dx python3 /app/desktop_probe.py 10.99.0.15 10.88.0.60 --routing-groups || status=1
check "client stayed up through the move (never saw an unassigned user)" \
  "dx pgrep -x aifree >/dev/null && ! dx grep -E 'stopping|no exit' /tmp/up.log >/dev/null"

echo "-- admin changes the STUN policy on the running client"
check "client reloaded the reject policy" 'set_stun_policy reject'
hits=$(stun_hits)
ux python3 /app/stun_probe.py reject 10.99.0.15 || status=1
check "the STUN responder received no request with reject" '[[ "$(stun_hits)" == "$hits" ]]'
protected_pid=$(tunnel_pid)
check "client reloaded the direct policy" 'set_stun_policy direct'
direct_pid=$(tunnel_pid)
check "switching to direct replaced the protected sing-box" \
  '[[ "$protected_pid" =~ ^[0-9]+$ && "$direct_pid" =~ ^[0-9]+$ && "$direct_pid" != "$protected_pid" ]] && ! dx kill -0 "$protected_pid" 2>/dev/null'
ux python3 /app/stun_probe.py direct 10.99.0.15 || status=1
check "client reloaded the proxy policy" 'set_stun_policy proxy'
ux python3 /app/stun_probe.py proxy 10.99.0.15 || status=1

echo "-- admin revokes the device; the client signs out and takes the tunnel down"
cpctl revoke hana hana-linux >/dev/null
# pgrep -x: exact process name (pgrep -f would match the sh -c running it)
for _ in $(seq 1 20); do dx pgrep -x aifree >/dev/null || break; sleep 1; done
check "aifree connect exited after revocation" "! dx pgrep -x aifree >/dev/null"
check "no sing-box left running" "! dx pgrep -x sing-box >/dev/null"
check "session forgotten" "ux aifree status | grep 'not signed in' >/dev/null"
check "TUN interface removed" "! dx ip link show dev tun-aifree >/dev/null 2>&1"
ux python3 /app/stun_probe.py disconnected 10.99.0.15 || status=1
dx cat /tmp/up.log | tail -n 4

echo "-- supervisor exits on its own: stop file, and stale heartbeat (the desktop app's two off-switches)"
ux sh -c 'AIFREE_PASSWORD=pw-hana-0123 aifree login --server http://10.88.0.5:8443 --user hana --device hana-linux >/dev/null && aifree sync >/dev/null'
dx sh -c 'cd /home/cust/.config/cc-proxy && rm -f stop connection-id; touch heartbeat; (aifree --state-dir /home/cust/.config/cc-proxy tunnel --heartbeat-timeout 0 >/tmp/t1.log 2>&1 &); sleep 3; touch stop; sleep 2'
check "stop file stops the supervisor" "ux aifree status | grep 'tunnel: stopped stopped by the app' >/dev/null"
dx sh -c 'cd /home/cust/.config/cc-proxy && rm -f stop connection-id; touch heartbeat; (aifree --state-dir /home/cust/.config/cc-proxy tunnel --heartbeat-timeout 3 >/tmp/t2.log 2>&1 &); sleep 7'
check "stale heartbeat stops the supervisor" "ux aifree status | grep 'heartbeats' >/dev/null"
check "and leaves no sing-box behind" "! dx pgrep -x sing-box >/dev/null"

echo "-- first launch from legacy user state, followed by the unprivileged CLI"
legacy_state=/home/cust/old-client-state
ux sh -c 'umask 077; mkdir "$1" && cp ~/.config/cc-proxy/session.json "$1/session.json"' sh "$legacy_state"
dx sh -c 'nohup aifree --state-dir "$1" up --interval 2 >/tmp/legacy-up.log 2>&1 &' sh "$legacy_state"
for _ in $(seq 1 20); do ux aifree --state-dir "$legacy_state" status | grep -q 'tunnel: running' && break; sleep 1; done
check "legacy up uses the saved session" "ux aifree --state-dir '$legacy_state' status | grep -q 'tunnel: running'"
check "the logged-in user owns the new locks" \
  "[ \"\$(dx stat -c '%U' '$legacy_state/session.lock' '$legacy_state/connection.lock' | sort -u)\" = cust ]"
ux aifree --state-dir "$legacy_state" disconnect || status=1
ux sh -c 'nohup aifree --state-dir "$1" connect --interval 2 >/tmp/new-up.log 2>&1 &' sh "$legacy_state"
for _ in $(seq 1 20); do ux aifree --state-dir "$legacy_state" status | grep -q 'tunnel: running' && break; sleep 1; done
check "the regular CLI reconnects and refreshes the legacy root-owned configuration" \
  "ux aifree --state-dir '$legacy_state' status | grep -q 'tunnel: running' && [ \"\$(dx stat -c '%U' '$legacy_state/sing-box.json')\" = cust ]"
ux aifree --state-dir "$legacy_state" disconnect || status=1

echo "== phase 4: alerts reach the webhook"
wait_alert() {  # STATUS RULE SUBJECT
  for _ in $(seq 1 40); do
    if compose logs --no-log-prefix sink 2>/dev/null | grep '^ALERT ' | cut -c7- | python3 -c "
import json, sys
want = tuple(sys.argv[1:])
sys.exit(0 if any((b['status'], b['rule'], b['subject']) == want for b in map(json.loads, sys.stdin)) else 1)" "$@"
    then echo "PASS webhook got $*"; return 0; fi
    sleep 1
  done
  echo "FAIL webhook never got $*"; return 1
}
wait_alert firing egress_probe_failing 10.99.0.6 || status=1
wait_alert firing entry_unreachable backup || status=1
cpctl ban 10.99.0.6 blocked by target >/dev/null
wait_alert resolved egress_probe_failing 10.99.0.6 || status=1
compose stop egress-jp >/dev/null 2>&1
wait_alert firing agent_stale jp-1 || status=1
compose logs --no-log-prefix sink | grep '^ALERT ' | cut -c7- | python3 -c "
import json, sys
for b in map(json.loads, sys.stdin): print('  %-8s %s' % (b['status'], b['text']))"

if [[ "${KEEP:-0}" == 1 ]]; then echo "dashboard: $CP/dashboard (admin token: $CP_ADMIN_TOKEN)"; fi
if [[ $status -eq 0 ]]; then echo "CP E2E PASS"; else echo "CP E2E FAIL"; fi
exit $status
