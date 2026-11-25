# Sourced by run-e2e.sh after the exit host is installed and synced (issue #61). Uses its variables and helpers
# (api, check, waitfor, port_status, frps_bytes, rnd, DB, NET, IP_*, FRP_DIR, SB_BIN, FRPS_TOKEN, OUT).
#
# The real ccproxy client on a Linux TUN (app mode), split as the desktop app is: the signed-in user `cust` runs
# `ccproxy headless` (the app's unprivileged half: sync, heartbeat, and the XTCP visitor through the `ccproxy visitor`
# guard and frpc 0.72.0), and root runs only the privileged supervisor `ccproxy tunnel` against cust's state directory,
# as the app's authorisation prompt does. The desktop app runs the same core code; only its window is not exercised.

echo "== desktop client: ccproxy runs the XTCP visitor itself (issue #61)"
docker run -d --name ccx-cp-http --network $NET --ip $IP_CP_HTTP -e DATABASE_URL="$DB" -e CP_ADMIN_TOKEN="$ADMIN_TOKEN" \
  ccx-cp serve --listen 0.0.0.0 >/dev/null
CPH="http://$IP_CP_HTTP:8443"
api PUT /admin/settings '{"client_policy": {"domain_suffix": ["target.test"], "direct_dns": "127.0.0.11"}}' >/dev/null
api POST /admin/users '{"name":"carol","password":"carol-password-0123"}' >/dev/null
api PUT /admin/users/carol '{"mode":"shared"}' >/dev/null
api POST /admin/users/carol/assign "{\"ip\":\"$IP_EXIT\",\"port\":20445}" >/dev/null
if waitfor 120 "carol's port ready" "port_status | grep -q '20445=ready'"; then
  echo "PASS carol's mapping (a derived key, not the primary one) is ready on the exit host"
else echo "FAIL carol's mapping: $(port_status)"; status=1; fi

# Like a real OS: the resolver is an off-link address the TUN hijacks (Docker's 127.0.0.11 is loopback).
docker run -d --name ccx-desktop --network $NET --ip $IP_DESKTOP --cap-add NET_ADMIN --device /dev/net/tun --init \
  --add-host other.test:$IP_ECHO -v "$FRP_DIR/frpc:/opt/aifree/frpc:ro" -v "$SB_BIN:/opt/aifree/sing-box:ro" \
  ccx-desktop sh -c "echo 'nameserver 192.0.2.53' > /etc/resolv.conf && exec sleep infinity" >/dev/null
docker exec ccx-desktop useradd -m -s /bin/sh cust
STATE=/home/cust/.config/cc-proxy
dx() { docker exec ccx-desktop "$@"; }          # root: the privileged supervisor, and inspection
ux() { docker exec -u cust ccx-desktop "$@"; }  # the signed-in user: everything the desktop app does unprivileged
up() {
  ux sh -c 'rm -f /tmp/up.log; nohup ccproxy headless --interval 2 > /tmp/up.log 2>&1 &'
  waitfor 30 "the unprivileged half" "logged 'start the tunnel with'"
  dx sh -c "nohup ccproxy --state-dir $STATE tunnel --singbox /opt/aifree/sing-box --heartbeat-timeout 10 > /tmp/tunnel.log 2>&1 &"
}
stop_up() { dx pkill -INT -x ccproxy || true; waitfor 20 "ccproxy to stop" "gone ccproxy"; }
gone() { ! dx pgrep -x "$1" >/dev/null; }
logged() { dx grep -q -- "$1" /tmp/up.log; }
via() { dx curl -q -sS --max-time 15 "http://$1:8080/${2:-}" 2>/dev/null || true; }
frpc_env_token() { dx sh -c 'p=$(pgrep -x frpc) && tr "\0" "\n" < /proc/$p/environ' 2>/dev/null | sed -n 's/^FRP_AUTH_TOKEN=//p'; }
start_jiffies() { dx sh -c "cut -d' ' -f22 /proc/\$(pgrep -x $1)/stat"; }

docker exec -u cust -e CCPROXY_PASSWORD=carol-password-0123 ccx-desktop ccproxy login --server $CPH --user carol --device carol-linux || status=1

echo "-- the privileged path runs no visitor (PR #64 review)"
check "ccproxy up (root) has no visitor option" "dx ccproxy up --visitor 2>&1 | grep -q \"unexpected argument '--visitor'\""
check "the visitor guard refuses root and starts no frpc" \
  "dx sh -c 'ccproxy --state-dir $STATE visitor --frpc /opt/aifree/frpc < /dev/null 2>&1' | grep -q 'must not run as root' && gone frpc"
check "ccproxy headless refuses root" "dx ccproxy --state-dir $STATE headless 2>&1 | grep -q 'must not run as root'"

echo "-- a busy local port is reported as such"
dx sh -c 'nohup python3 -m http.server 20445 --bind 127.0.0.1 >/dev/null 2>&1 &'
sleep 1
up
if waitfor 60 "busy-port failure" "logged 'Local port 20445 is already in use'"; then echo "PASS busy port: its own message"
else echo "FAIL busy port: $(dx tail -n 5 /tmp/up.log)"; status=1; fi
check "and no frpc stayed behind" "gone frpc"
check "and the tunnel never reported connected" "! logged 'xtcp visitor: running'"
stop_up
dx pkill -f 'http.server 20445' || true

echo "-- connect: the TUN first, then frpc; connected only when a direct path is open"
up
if waitfor 90 "visitor ready" "logged 'xtcp visitor: running'"; then echo "PASS the client reports connected once the visitor is ready"
else echo "FAIL visitor not ready: $(dx tail -n 20 /tmp/up.log)"; status=1; fi
check "frpc started after sing-box (the TUN was up first)" "[ \"\$(start_jiffies frpc)\" -ge \"\$(start_jiffies sing-box)\" ]"
check "frpc is the pinned $FRP_VERSION, run from next to ccproxy with the visitor file" \
  "dx /opt/aifree/frpc -v | grep -qx $FRP_VERSION && dx pgrep -f '^/opt/aifree/frpc -c $STATE/frpc-visitor.toml\$' >/dev/null"
waitfor 60 "first request through the visitor" "[ -n \"\$(via target.test)\" ]" || status=1
SEEN=$(via target.test)
check "target.test leaves via the exit host's egress IPv4 ($IP_EXIT, seen: $SEEN)" "[ '$SEEN' = '$IP_EXIT' ]"
# The desktop app's public exit check (exit_probe.rs): `sing-box tools fetch` through a config holding only the client
# config's egress outbound (runtime::render_exit_probe), so it dials the visitor too. Here it fetches the echo server.
exit_probe() {
  dx python3 -c "
import json
c = json.load(open('$STATE/sing-box.json'))
print(json.dumps({'log': {'disabled': True}, 'outbounds': [c['outbounds'][0]],
                  'dns': {'servers': [c['dns']['servers'][1]], 'final': 'direct-dns'},
                  'route': {'final': 'egress', 'auto_detect_interface': True, 'default_domain_resolver': 'direct-dns'}}))
" > "$OUT/probe.json"
  docker cp "$OUT/probe.json" ccx-desktop:/tmp/probe.json >/dev/null
  dx /opt/aifree/sing-box -c /tmp/probe.json tools fetch --outbound egress "http://$IP_ECHO:8080/" 2>/dev/null | tr -d '\r\n' || true
}
PROBED=$(exit_probe)
check "the public exit check agrees: the exit probe sees $IP_EXIT (got: $PROBED)" "[ '$PROBED' = '$IP_EXIT' ]"
check "other.test is not proxied (seen as $IP_DESKTOP)" "[ \"\$(via other.test)\" = '$IP_DESKTOP' ]"
check "the default route goes through the TUN" "dx ip route get 1.1.1.1 | grep -q 'dev tun'"
before=$(frps_bytes)
got=$(dx curl -q -sS --max-time 90 -o /dev/null -w '%{size_download}' http://target.test:8080/big || true)
after=$(frps_bytes)
check "20 MB through the client's visitor, frps carried $((after - before)) bytes (< 1 MB)" \
  "[ '$got' = $((20 << 20)) ] && [ $((after - before)) -lt 1048576 ]"
check "visitor files are 0600" \
  "[ \"\$(dx sh -c 'cd $STATE && stat -c %a frpc-visitor.toml frp-ca.pem frp-token visitor.json frpc.log visitor-status.json | sort -u')\" = 600 ]"
check "the frps token is on no command line" "! dx ps -eo args | grep -qF -- '$FRPS_TOKEN'"
check "the token reached frpc through its environment" "[ \"\$(frpc_env_token)\" = '$FRPS_TOKEN' ]"
check "frpc runs as the signed-in user, not root" "[ \"\$(dx ps -o user= -p \$(dx pgrep -x frpc))\" = cust ] && ! dx pgrep -u root -x frpc >/dev/null"
check "the visitor guard runs as the signed-in user" "[ \"\$(dx ps -o user= -p \$(dx pgrep -f 'ccproxy --state-dir $STATE visitor'))\" = cust ]"
check "root runs only the supervisor and sing-box" "dx pgrep -u root -f 'ccproxy --state-dir $STATE tunnel' >/dev/null && dx pgrep -u root -x sing-box >/dev/null"
check "the frps token and visitor key appear in no log, status or info file" \
  "! dx sh -c 'cat /tmp/up.log $STATE/frpc.log $STATE/visitor-status.json $STATE/visitor.json /var/lib/ccproxy/status.json /var/lib/ccproxy/tunnel.log /tmp/tunnel.log 2>/dev/null' | grep -q -e '$FRPS_TOKEN' -e 'secretKey'"

echo "-- stop (Ctrl-C): no frpc, no sing-box"
stop_up
check "stop leaves no frpc and no sing-box" "gone frpc && gone sing-box"

echo "-- a blocked hole punch is reported and never relayed"
docker exec ccx-exit sh -c "iptables -I INPUT -p udp -s $IP_DESKTOP -j DROP && iptables -I OUTPUT -p udp -d $IP_DESKTOP -j DROP"
up
if waitfor 120 "hole-punch failure" "logged 'hole punching failed'"; then echo "PASS blocked UDP: the client reports failed hole punching"
else echo "FAIL no hole-punch message: $(dx tail -n 10 /tmp/up.log)"; status=1; fi
check "and never reported connected" "! logged 'xtcp visitor: running'"
check "frpc keeps its own bounded retries (still running)" "! gone frpc"
stop_up
docker exec ccx-exit sh -c "iptables -D INPUT -p udp -s $IP_DESKTOP -j DROP && iptables -D OUTPUT -p udp -d $IP_DESKTOP -j DROP"

echo "-- the client crashes (SIGKILL): frpc goes with it"
up
waitfor 90 "visitor ready" "logged 'xtcp visitor: running'" || status=1
dx pkill -KILL -f 'ccproxy headless' || true
if waitfor 15 "frpc after the crash" "gone frpc"; then echo "PASS frpc exited after the client was killed"
else echo "FAIL frpc outlived a killed client"; status=1; fi
if waitfor 30 "sing-box after the crash" "gone sing-box"; then echo "PASS the supervisor stopped on the stale heartbeat"
else echo "FAIL sing-box outlived a killed client"; status=1; fi
waitfor 20 "the supervisor to exit" "gone ccproxy" || status=1

echo "-- the frps token is rotated: the next sync applies it and the tunnel recovers"
up
waitfor 90 "visitor ready" "logged 'xtcp visitor: running'" || status=1
NEW_FRPS_TOKEN="frps-$(rnd)"
sed -i.bak "s/^auth.token = .*/auth.token = \"$NEW_FRPS_TOKEN\"/" "$OUT/frps.toml" && rm -f "$OUT/frps.toml.bak"
api PUT /admin/hosts/macmini-sg-208/xtcp "{\"auth_token\":\"$NEW_FRPS_TOKEN\"}" >/dev/null
docker restart ccx-frps >/dev/null
OLD_FRPS_TOKEN=$FRPS_TOKEN FRPS_TOKEN=$NEW_FRPS_TOKEN
if waitfor 240 "tunnel after rotation" "[ \"\$(frpc_env_token)\" = '$NEW_FRPS_TOKEN' ] && [ \"\$(via target.test)\" = '$IP_EXIT' ]"; then
  echo "PASS after rotation the client's frpc runs with the new token and traffic leaves via $IP_EXIT"
else echo "FAIL rotation: $(dx tail -n 8 /tmp/up.log)"; status=1; fi
check "the old and new tokens appear in no client log" "! dx sh -c 'cat /tmp/up.log $STATE/frpc.log $STATE/visitor-status.json' | grep -q -e '$OLD_FRPS_TOKEN' -e '$NEW_FRPS_TOKEN'"

echo "-- the device is revoked: the client signs out, stops, and removes the visitor"
api POST /admin/users/carol/devices/carol-linux/revoke >/dev/null
if waitfor 30 "ccproxy to exit after revocation" "gone ccproxy"; then echo "PASS the client and the supervisor exited after revocation"
else echo "FAIL ccproxy still running after revocation"; status=1; fi
check "revocation leaves no frpc and no sing-box" "gone frpc && gone sing-box"
check "session and visitor files removed" \
  "! dx sh -c 'ls $STATE/session.json $STATE/frpc-visitor.toml $STATE/frp-ca.pem $STATE/frp-token $STATE/visitor.json 2>/dev/null' | grep -q ."
check "the revoked device gets 401 from /v1/xtcp-visitor" \
  "[ \"\$(dx curl -q -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer nope' $CPH/v1/xtcp-visitor)\" = 401 ]"
dx tail -n 3 /tmp/up.log | sed 's/^/  client: /'
