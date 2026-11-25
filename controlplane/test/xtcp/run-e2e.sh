#!/usr/bin/env bash
# XTCP exit-node e2e: the real installer, services, frpc and data path on an isolated Docker network.
#
#   pg       PostgreSQL for the control plane
#   cp       this checkout's Go control plane (image from controlplane/Dockerfile), TLS, serving the agent dist
#   frps     official frps 0.72.0 on TCP 7003: TLS with a test CA, token auth (rendezvous only)
#   exit     a systemd Linux host. It downloads exit.sh as the copied install command does, and the installer fetches
#            the agent from cp and sing-box 1.14.4 and frpc 0.72.0 from GitHub (SHA-256 pinned)
#   visitor  official frpc as the XTCP visitor (QUIC, no fallback) on 127.0.0.1:20443, and a sing-box client built
#            from aifree's own client config (/v1/config?mode=proxy) on 127.0.0.1:2080
#   echo     answers with the caller's IPv4 (and /big with 20 MB)
#
# Checks: XTCP registration; the agent's XTCP sync under systemd (installed file confirmed without reload, a second
# shared port hot-reloaded and confirmed without rerunning the installer, release removes the proxy, ready after a
# reboot); the proxied request leaves from the exit host's egress IPv4; a 20 MB transfer does not pass through frps;
# managed agent updates (issue #67) with two user ports: a host outside the rollout and a paused rollout keep the
# release, a tampered release is refused, the agent then moves to the signed release by itself through systemd while
# Direct and XTCP traffic of both users keeps flowing (sing-box and frpc untouched), and a release whose agent fails
# to start is rolled back; a blocked hole punch closes the connection with no relay; services come back after a
# reboot without login; uninstall removes them. Needs Docker (with systemd containers) and internet access (GitHub,
# STUN). The agents in this test trust a throwaway release key (AGENT_EXTRA_RELEASE_KEYS), never a production one.
#   controlplane/test/xtcp/run-e2e.sh            KEEP=1 leaves the containers running
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="$HERE/out"
NET=ccx-e2e
SUBNET=172.31.90.0/24
IP_CP=172.31.90.5 IP_FRPS=172.31.90.10 IP_EXIT=172.31.90.20 IP_VISITOR=172.31.90.30 IP_ECHO=172.31.90.40
FRP_VERSION=0.72.0
SINGBOX_VERSION=1.14.4
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
rnd() { openssl rand -hex 24; }
ADMIN_TOKEN="admin-$(rnd)" FRPS_TOKEN="frps-$(rnd)" XTCP_KEY="xtcp-$(rnd)" PG_PASSWORD="pg-$(rnd)"
CONTAINERS="ccx-pg ccx-cp ccx-frps ccx-exit ccx-visitor ccx-echo"

cleanup() {
  docker exec ccx-exit journalctl -u ccproxy-exit-agent --no-pager > "$OUT/exit-agent.journal" 2>/dev/null || true
  docker cp ccx-visitor:/tmp/visitor.log "$OUT/" >/dev/null 2>&1 || true
  docker cp ccx-visitor:/tmp/visitor-blocked.log "$OUT/" >/dev/null 2>&1 || true
  if [[ "${KEEP:-0}" != 1 ]]; then
    docker rm -f $CONTAINERS >/dev/null 2>&1 || true
    docker network rm $NET >/dev/null 2>&1 || true
    rm -rf "$OUT/tls" "$OUT/frps.toml" "$OUT/visitor.toml" "$OUT/client.json" "$OUT/release.key" \
      "$OUT/bob-visitor.toml" "$OUT/bob-client.json" "$OUT/direct-client.json"   # test credentials
  fi
}
trap cleanup EXIT
status=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; status=1; fi; }
waitfor() { # waitfor SECONDS DESCRIPTION COMMAND
  local deadline=$((SECONDS + $1))
  until eval "$3"; do
    if (( SECONDS >= deadline )); then echo "timed out waiting for $2" >&2; return 1; fi
    sleep 1
  done
}

docker rm -f $CONTAINERS >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
rm -rf "$OUT" && mkdir -p "$OUT/tls" "$OUT/frp" "$OUT/dist"
chmod 700 "$OUT"

echo "== build: agent dist and signed test releases, control-plane image, test images"
V1=agent-e2e-v1 V2=agent-e2e-v2 V3=agent-e2e-v3-broken
(
  cd "$REPO/egress/agent"
  go run ./cmd/agent-release keygen "$OUT/release.key" > "$OUT/release-keys.txt"
  export AGENT_EXTRA_RELEASE_KEYS; AGENT_EXTRA_RELEASE_KEYS=$(cat "$OUT/release-keys.txt")
  ./build.sh "$V1" >/dev/null 2>&1                     # what the installer serves (CP_AGENT_DIST)
  cp dist/* "$OUT/dist/"
  publish() { # publish DIST_DIR VERSION SEQUENCE: a signed release in $OUT/releases/VERSION, as the workflow makes it
    mkdir -p "$OUT/releases/$2" && cp "$1"/* "$OUT/releases/$2/"
    go run ./cmd/agent-release record -dist "$OUT/releases/$2" -sequence "$3" -commit "$(git rev-parse HEAD)" >/dev/null
    go run ./cmd/agent-release sign -dist "$OUT/releases/$2" -key-file "$OUT/release.key" >/dev/null
    go run ./cmd/agent-release verify -dist "$OUT/releases/$2" -keys "$OUT/release-keys.txt"
  }
  ./build.sh "$V2" >/dev/null 2>&1
  publish dist "$V2" 2
  # A broken release: its agent exits right after starting (the rollback rehearsal).
  rm -rf "$OUT/broken-src" && mkdir "$OUT/broken-src" && cp -R ./*.go go.mod build.sh release_keys.txt release cmd "$OUT/broken-src/"
  perl -0pi -e 's/^\tagent\.attachUpdater\(upd\)\n/\tagent.attachUpdater(upd)\n\tlogf("broken test release: exiting at start")\n\treturn 3\n/m' "$OUT/broken-src/main.go"
  grep -q 'broken test release' "$OUT/broken-src/main.go"
  (cd "$OUT/broken-src" && ./build.sh "$V3" >/dev/null 2>&1)
  publish "$OUT/broken-src/dist" "$V3" 3
)
docker build -q -t ccx-cp "$REPO/controlplane" >/dev/null
docker build -q -t ccx-systemd - >/dev/null <<'EOF'
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus sudo curl \
    ca-certificates iproute2 iptables procps >/dev/null && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service console-getty.service systemd-logind.service >/dev/null 2>&1 || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker build -q -t ccx-tools - >/dev/null <<'EOF'
FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates python3 procps >/dev/null \
 && rm -rf /var/lib/apt/lists/*
EOF

echo "== frp $FRP_VERSION and sing-box $SINGBOX_VERSION for the test peers (checked against the installer's pins)"
pin() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['assets'][sys.argv[2]][sys.argv[3]])" "$@"; }
fetch() { # fetch PINS_FILE URL_PREFIX DEST_DIR
  local file sha; file=$(pin "$1" "linux-$ARCH" file); sha=$(pin "$1" "linux-$ARCH" sha256)
  curl -q --proto '=https' --proto-redir '=https' -fsSL -o "$3/$file" "$2/$file"
  echo "$sha  $3/$file" | shasum -a 256 -c - >/dev/null
  tar -xzf "$3/$file" -C "$3"
}
fetch "$REPO/controlplane/install/frpc.json" "https://github.com/fatedier/frp/releases/download/v$FRP_VERSION" "$OUT/frp"
fetch "$REPO/controlplane/install/sing-box.json" "https://github.com/SagerNet/sing-box/releases/download/v$SINGBOX_VERSION" "$OUT/frp"
FRP_DIR="$OUT/frp/frp_${FRP_VERSION}_linux_$ARCH"
SB_BIN="$OUT/frp/sing-box-$SINGBOX_VERSION-linux-$ARCH/sing-box"

echo "== test CA: certificates for cp and frps"
(
  cd "$OUT/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 2 \
    -subj "/CN=aifree XTCP e2e CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=keyCertSign" 2>/dev/null
  for name in cp frps; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $name.key -out $name.csr -subj "/CN=$name" 2>/dev/null
    printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' $name > $name.ext
    openssl x509 -req -in $name.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out $name.pem -days 2 -extfile $name.ext 2>/dev/null
  done
  chmod 644 ./*.pem ./*.key
)

echo "== start pg, cp, frps, echo"
docker network create --subnet $SUBNET $NET >/dev/null
docker run -d --name ccx-pg --network $NET -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB=cp postgres:16 >/dev/null
waitfor 60 "postgres" "docker exec ccx-pg pg_isready -q -U postgres 2>/dev/null"
DB="postgresql://postgres:$PG_PASSWORD@ccx-pg:5432/cp?sslmode=disable"
docker run --rm --network $NET -e DATABASE_URL="$DB" ccx-cp init >/dev/null
docker run -d --name ccx-cp --network $NET --ip $IP_CP --network-alias cp -e DATABASE_URL="$DB" -e CP_ADMIN_TOKEN="$ADMIN_TOKEN" \
  -e CP_AGENT_DIST=/agent-dist -v "$OUT/dist:/agent-dist:ro" -e CP_AGENT_RELEASES=/agent-releases -v "$OUT/releases:/agent-releases:ro" \
  -v "$OUT/tls:/tls:ro" \
  ccx-cp serve --listen 0.0.0.0 --tls-cert /tls/cp.pem --tls-key /tls/cp.key >/dev/null
cat > "$OUT/frps.toml" <<EOF
bindPort = 7003
auth.method = "token"
auth.token = "$FRPS_TOKEN"
transport.tls.force = true
transport.tls.certFile = "/tls/frps.pem"
transport.tls.keyFile = "/tls/frps.key"
log.to = "console"
EOF
docker run -d --name ccx-frps --network $NET --ip $IP_FRPS --network-alias frps -v "$FRP_DIR/frps:/usr/local/bin/frps:ro" \
  -v "$OUT/frps.toml:/etc/frps.toml:ro" -v "$OUT/tls:/tls:ro" ccx-tools frps -c /etc/frps.toml >/dev/null
cat > "$OUT/echo.py" <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b"x" * (20 << 20)) if self.path == "/big" else (self.client_address[0] + "\n").encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
docker run -d --name ccx-echo --network $NET --ip $IP_ECHO -v "$OUT/echo.py:/echo.py:ro" ccx-tools python3 /echo.py >/dev/null
docker run -d --name ccx-exit --hostname macmini-sg-208 --network $NET --ip $IP_EXIT --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock ccx-systemd >/dev/null

api() { # api METHOD PATH [JSON]  (admin token via a curl config on stdin, inside the exit container's network)
  printf 'header = "Authorization: Bearer %s"\n' "$ADMIN_TOKEN" |
    docker exec -i ccx-visitor-api curl -q -sS --config - --cacert /tls/ca.pem -X "$1" -H 'Content-Type: application/json' \
      ${3:+-d "$3"} "https://cp:8443$2"
}
docker run -d --name ccx-visitor --network $NET --ip $IP_VISITOR -v "$OUT/tls:/tls:ro" -v "$FRP_DIR/frpc:/usr/local/bin/frpc:ro" \
  -v "$SB_BIN:/usr/local/bin/sing-box:ro" ccx-tools sleep infinity >/dev/null
CONTAINERS="$CONTAINERS ccx-visitor-api"
docker run -d --name ccx-visitor-api --network $NET -v "$OUT/tls:/tls:ro" ccx-tools sleep infinity >/dev/null
waitfor 60 "control plane health" "api GET /healthz 2>/dev/null | grep -q ok"

echo "== control plane: host macmini-sg-208 on XTCP, user alice on entry port 20443"
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
HOST_TOKEN=$(api POST /admin/hosts '{"name":"macmini-sg-208","public_host":"127.0.0.1","server_name":"www.cloudflare.com","port_min":20000,"port_max":20999,"block_private":false,"block_cidrs":["169.254.169.254/32"]}' | json '["agent_token"]')
api POST /admin/hosts/macmini-sg-208/ips "{\"ips\":[\"$IP_EXIT\"]}" >/dev/null
api POST /admin/users '{"name":"alice","password":"alice-password-0123"}' >/dev/null
api POST /admin/users/alice/assign "{\"ip\":\"$IP_EXIT\",\"port\":20443}" >/dev/null
CA_JSON=$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$OUT/tls/ca.pem")
api PUT /admin/hosts/macmini-sg-208/xtcp "{\"server_addr\":\"$IP_FRPS\",\"server_port\":7003,\"tls_server_name\":\"frps\",\"ca_pem\":$CA_JSON,\"auth_token\":\"$FRPS_TOKEN\",\"proxy_name\":\"ccproxy-208-direct\",\"secret_key\":\"$XTCP_KEY\",\"local_port\":20443}" > "$OUT/xtcp-view.json"
check "admin view hides the XTCP secrets" "! grep -q -e '$FRPS_TOKEN' -e '$XTCP_KEY' '$OUT/xtcp-view.json' && grep -q '\"transport\":\"xtcp\"' '$OUT/xtcp-view.json'"
CMD=$(api GET "/admin/install-commands?cp=https://cp:8443" | json '["linux"]["install"]')
echo "copied command: $CMD"

echo "== exit host: install with the copied command (token from a root-only file instead of the prompt)"
docker exec -i ccx-exit sh -c 'cat > /usr/local/share/ca-certificates/ccx-e2e.crt && update-ca-certificates >/dev/null' < "$OUT/tls/ca.pem"
printf '%s\n' "$HOST_TOKEN" | docker exec -i ccx-exit sh -c 'umask 077; cat > /root/agent.token'
# The copied command, with the interactive prompt replaced by --token-file (no TTY in docker exec).
RUN=$(printf '%s' "$CMD" | sed "s|--cp 'https://cp:8443'|& --token-file /root/agent.token|")
docker exec ccx-exit sh -c "$RUN" > "$OUT/install.log" 2>&1 || { cat "$OUT/install.log"; exit 1; }
cat "$OUT/install.log"
check "installer exit status and transport" "grep -q 'transport: XTCP' '$OUT/install.log' && grep -q 'installed.' '$OUT/install.log'"
check "no secret in the installer output" "! grep -q -e '$HOST_TOKEN' -e '$FRPS_TOKEN' -e '$XTCP_KEY' '$OUT/install.log'"
check "frpc.toml is root-only (0600)" "[ \"\$(docker exec ccx-exit stat -c %a:%U /etc/ccproxy-exit/frpc.toml)\" = 600:root ]"
check "frpc is the pinned 0.72.0" "docker exec ccx-exit /opt/ccproxy-exit/bin/frpc -v | grep -qx $FRP_VERSION"
for unit in ccproxy-exit-agent ccproxy-exit-singbox ccproxy-exit-frpc; do
  waitfor 60 "$unit" "docker exec ccx-exit systemctl is-active --quiet $unit"
  check "$unit active and enabled at boot" "docker exec ccx-exit systemctl is-enabled --quiet $unit"
done
waitfor 60 "XTCP registration" "docker exec ccx-exit journalctl -u ccproxy-exit-frpc --no-pager | grep -q 'start proxy success'"
check "frpc registered the xtcp proxy with frps" "docker logs ccx-frps 2>&1 | grep -q 'new proxy \[ccproxy-208-direct\] type \[xtcp\] success'"
waitfor 60 "sing-box on 20443" "docker exec ccx-exit sh -c 'ss -ltn | grep -q :20443'"
echo "PASS sing-box listens on 20443"

echo "== agent XTCP sync under systemd (issue #45)"
sync_state() { api GET /admin/hosts/macmini-sg-208/xtcp | json '["sync"]["state"]'; }
port_status() { api GET /admin/hosts/macmini-sg-208/xtcp | python3 -c "import json,sys; print(' '.join('%d=%s' % (m['port'], m['status']) for m in json.load(sys.stdin)['mappings']))"; }
frpc_main_pid() { docker exec ccx-exit systemctl show -p MainPID --value ccproxy-exit-frpc; }
if waitfor 90 "XTCP sync ready after install" "[ \"\$(sync_state)\" = ready ]"; then echo "PASS the installed agent confirmed the XTCP mapping"
else echo "FAIL XTCP sync after install: $(sync_state)"; status=1; fi
check "the installer wrote frpc's loopback admin API and the restart helper" \
  "docker exec ccx-exit grep -q '^webServer.addr = \"127.0.0.1\"' /etc/ccproxy-exit/frpc.toml && docker exec ccx-exit grep -q 'systemctl restart ccproxy-exit-frpc.service' /opt/ccproxy-exit/libexec/frpc-ctl"
check "the fresh install needed no reload (the installed file is the agent's candidate)" \
  "docker exec ccx-exit journalctl -u ccproxy-exit-agent --no-pager | grep -q 'frpc confirmed generation .* (already in place)'"
check "the admin password file is root-only" "[ \"\$(docker exec ccx-exit stat -c %a:%U /var/lib/ccproxy-exit/agent/frpc-admin.secret)\" = 600:root ]"
FRPC_PID=$(frpc_main_pid)
api PUT /admin/users/alice '{"mode":"shared"}' >/dev/null
api POST /admin/users '{"name":"bob","password":"bob-password-0123"}' >/dev/null
api PUT /admin/users/bob '{"mode":"shared"}' >/dev/null
api POST /admin/users/bob/assign "{\"ip\":\"$IP_EXIT\",\"port\":20444}" >/dev/null
assigned=$SECONDS
if waitfor 120 "bob's port ready" "[ \"\$(port_status)\" = '20443=ready 20444=ready' ]"; then echo "PASS a second shared port became ready through agent sync in $((SECONDS - assigned))s, no installer rerun"
else echo "FAIL second port: $(port_status)"; status=1; fi
check "frps registered the second proxy" "docker logs ccx-frps 2>&1 | grep -q 'new proxy \[ccproxy-208-direct-20444\] type \[xtcp\] success'"
check "systemd's frpc was hot-reloaded, not restarted (MainPID unchanged)" "[ \"\$(frpc_main_pid)\" = '$FRPC_PID' ]"
api POST /admin/users/bob/release >/dev/null
if waitfor 120 "bob released" "[ \"\$(port_status)\" = '20443=ready' ]"; then echo "PASS after release only the primary mapping remains"
else echo "FAIL release: $(port_status)"; status=1; fi
check "frps closed the retired proxy" "docker logs ccx-frps 2>&1 | grep -q 'close proxy \[ccproxy-208-direct-20444\] success'"

echo "== visitor: frpc xtcp visitor (no fallback) and the aifree client config"
cat > "$OUT/visitor.toml" <<EOF
serverAddr = "$IP_FRPS"
serverPort = 7003
auth.method = "token"
auth.token = "$FRPS_TOKEN"
transport.tls.enable = true
transport.tls.trustedCaFile = "/tls/ca.pem"
transport.tls.serverName = "frps"
log.to = "console"

[[visitors]]
name = "ccproxy-208-visitor"
type = "xtcp"
serverName = "ccproxy-208-direct"
secretKey = "$XTCP_KEY"
bindAddr = "127.0.0.1"
bindPort = 20443
protocol = "quic"
EOF
docker cp "$OUT/visitor.toml" ccx-visitor:/etc/visitor.toml >/dev/null
check "visitor has no fallback" "! grep -qi fallback '$OUT/visitor.toml'"
docker exec -d ccx-visitor sh -c 'frpc -c /etc/visitor.toml > /tmp/visitor.log 2>&1'
DEVICE_TOKEN=$(printf '{"username":"alice","password":"alice-password-0123","device":"macbook"}' |
  docker exec -i ccx-visitor-api curl -q -sS --cacert /tls/ca.pem -H 'Content-Type: application/json' -d @- https://cp:8443/v1/login | json '["token"]')
printf 'header = "Authorization: Bearer %s"\n' "$DEVICE_TOKEN" |
  docker exec -i ccx-visitor-api curl -q -sS --config - --cacert /tls/ca.pem "https://cp:8443/v1/config?mode=proxy" > "$OUT/client.json"
check "client config points at the local XTCP entry" "grep -q '\"server\": *\"127.0.0.1\"' '$OUT/client.json' && grep -q '\"server_port\": *20443' '$OUT/client.json'"
docker cp "$OUT/client.json" ccx-visitor:/etc/client.json >/dev/null
docker exec -d ccx-visitor sh -c 'sing-box run -c /etc/client.json > /tmp/client.log 2>&1'
sleep 3

proxied() { docker exec ccx-visitor curl -q -sS --max-time 20 -x socks5h://127.0.0.1:2080 "$@"; }
frps_bytes() { docker exec ccx-frps sh -c 'cat /sys/class/net/eth0/statistics/rx_bytes /sys/class/net/eth0/statistics/tx_bytes' | paste -sd+ - | bc; }
waitfor 90 "first proxied request" "proxied http://$IP_ECHO:8080/ >/dev/null 2>&1"
SEEN=$(proxied "http://$IP_ECHO:8080/")
check "aifree's observed IPv4 is the exit host's egress IPv4 ($IP_EXIT)" "[ '$SEEN' = '$IP_EXIT' ]"
check "the visitor punched a direct path" "docker exec ccx-visitor grep -Eqi 'nathole|establish|success' /tmp/visitor.log"
before=$(frps_bytes)
got=$(proxied -o /dev/null -w '%{size_download}' "http://$IP_ECHO:8080/big")
after=$(frps_bytes)
echo "20 MB transfer: downloaded $got bytes; frps interface counters $before -> $after ($((after - before)) bytes)"
check "20 MB through the tunnel, frps carried under 1 MB" "[ '$got' = $((20 << 20)) ] && [ $((after - before)) -lt 1048576 ]"

echo "== automatic agent update (issue #67): two user ports, Direct and XTCP, normal service execution"
host_field() { # host_field KEY: this host's field in GET /admin/agent-rollout
  api GET /admin/agent-rollout | python3 -c "import json,sys; print([h for h in json.load(sys.stdin)['hosts'] if h['host']=='macmini-sg-208'][0]['$1'])"
}
running_version() { docker exec ccx-exit /opt/ccproxy-exit/bin/ccproxy-exit-agent version | awk '{print $2}'; }
unit_pid() { docker exec ccx-exit systemctl show -p MainPID --value "$1"; }
agent_restarts() { docker exec ccx-exit systemctl show -p NRestarts --value ccproxy-exit-agent; }
# agent_logged PATTERN: the agent's journal has a matching line. Saved to a file first: with pipefail, journalctl piped
# into grep -q fails (SIGPIPE) when the match comes early in a long journal.
agent_logged() { docker exec ccx-exit journalctl -u ccproxy-exit-agent --no-pager > "$OUT/agent-journal.txt"; grep -q -- "$1" "$OUT/agent-journal.txt"; }
# bob back on the second port, with his own visitor (user key) and client; a Direct client that reaches alice's
# sing-box listener on the exit host without frp.
api POST /admin/users/bob/assign "{\"ip\":\"$IP_EXIT\",\"port\":20444}" >/dev/null
waitfor 120 "both ports ready" "[ \"\$(port_status)\" = '20443=ready 20444=ready' ]"
BOB_TOKEN=$(printf '{"username":"bob","password":"bob-password-0123","device":"laptop"}' |
  docker exec -i ccx-visitor-api curl -q -sS --cacert /tls/ca.pem -H 'Content-Type: application/json' -d @- https://cp:8443/v1/login | json '["token"]')
printf 'header = "Authorization: Bearer %s"\n' "$BOB_TOKEN" |
  docker exec -i ccx-visitor-api curl -q -sS --config - --cacert /tls/ca.pem "https://cp:8443/v1/config?mode=proxy" |
  python3 -c "import json,sys; c=json.load(sys.stdin); c['inbounds'][0]['listen_port']=2081; json.dump(c, sys.stdout)" > "$OUT/bob-client.json"
api GET "/admin/users/bob/xtcp-visitor?ca_file=/tls/ca.pem" | json '["frpc_toml"]' > "$OUT/bob-visitor.toml"
python3 -c "import json,sys; c=json.load(open(sys.argv[1])); c['inbounds'][0]['listen_port']=2082; c['outbounds'][0]['server']=sys.argv[2]; json.dump(c, sys.stdout)" \
  "$OUT/client.json" "$IP_EXIT" > "$OUT/direct-client.json"
docker cp "$OUT/bob-client.json" ccx-visitor:/etc/bob-client.json >/dev/null
docker cp "$OUT/bob-visitor.toml" ccx-visitor:/etc/bob-visitor.toml >/dev/null
docker cp "$OUT/direct-client.json" ccx-visitor:/etc/direct-client.json >/dev/null
docker exec -e FRP_AUTH_TOKEN="$FRPS_TOKEN" ccx-visitor sh -c '(frpc -c /etc/bob-visitor.toml > /tmp/bob-visitor.log 2>&1 &); (sing-box run -c /etc/bob-client.json > /tmp/bob-client.log 2>&1 &); (sing-box run -c /etc/direct-client.json > /tmp/direct-client.log 2>&1 &)'
via() { docker exec ccx-visitor curl -q -sS --max-time 20 -x "socks5h://127.0.0.1:$1" "http://$IP_ECHO:8080/" 2>/dev/null; }
if waitfor 90 "bob through XTCP" "[ \"\$(via 2081)\" = $IP_EXIT ]"; then echo "PASS bob (second port, own visitor key) leaves from $IP_EXIT"
else echo "FAIL bob through XTCP"; status=1; fi
if waitfor 30 "alice Direct" "[ \"\$(via 2082)\" = $IP_EXIT ]"; then echo "PASS alice's Direct entry (sing-box listener, no frp) leaves from $IP_EXIT"
else echo "FAIL alice Direct"; status=1; fi
check "the installed agent runs and reports $V1 (heartbeat agent_version)" "[ \"\$(running_version)\" = $V1 ] && [ \"\$(host_field agent_version)\" = $V1 ]"
check "it reports its updater idle (no rollout)" "[ \"\$(host_field state)\" = idle ]"
check "the control plane lists the signed releases $V2 and $V3" "api GET /admin/agent-releases | grep -q '\"$V2\"' && api GET /admin/agent-releases | grep -q '\"$V3\"'"

api POST /admin/hosts '{"name":"other-host","public_host":"192.0.2.99","server_name":"www.cloudflare.com","port_min":21000,"port_max":21099}' >/dev/null
api PUT /admin/agent-rollout "{\"version\":\"$V2\",\"hosts\":[\"other-host\"]}" >/dev/null
docker exec ccx-exit systemctl restart ccproxy-exit-agent   # an immediate rollout check, instead of the next one in 2 minutes
sleep 20
check "a host outside the rollout keeps $V1" "[ \"\$(running_version)\" = $V1 ] && [ \"\$(host_field outcome)\" = not_targeted ]"
api PUT /admin/agent-rollout "{\"version\":\"$V2\",\"hosts\":[\"macmini-sg-208\"],\"paused\":true}" >/dev/null
docker exec ccx-exit systemctl restart ccproxy-exit-agent
sleep 20
check "a paused rollout does not upgrade the targeted host" "[ \"\$(running_version)\" = $V1 ] && [ \"\$(host_field outcome)\" = waiting ]"

BIN="$OUT/releases/$V2/ccproxy-exit-agent-linux-$ARCH"
cp "$BIN" "$OUT/good-binary" && printf 'tampered' >> "$BIN"
api POST /admin/agent-rollout/resume >/dev/null
docker exec ccx-exit systemctl restart ccproxy-exit-agent
if waitfor 60 "the refused download is reported" "[ \"\$(host_field state)\" = failed ]"; then echo "PASS a tampered release binary is refused: $(host_field error)"
else echo "FAIL tampered binary: state $(host_field state)"; status=1; fi
check "and the host keeps running $V1 with both ports ready" "[ \"\$(running_version)\" = $V1 ] && [ \"\$(port_status)\" = '20443=ready 20444=ready' ]"
cp "$OUT/good-binary" "$BIN"

# From here on the agent works alone: its next periodic check (at most --update-interval, 120 s) finds the release.
SB_PID=$(unit_pid ccproxy-exit-singbox) FRPC_PID=$(unit_pid ccproxy-exit-frpc) RESTARTS=$(agent_restarts)
docker exec -d ccx-visitor sh -c 'rm -f /tmp/upd-*.out /tmp/upd.stop; for p in 2080 2081 2082; do (while [ ! -f /tmp/upd.stop ]; do if curl -q -sS --max-time 5 -x socks5h://127.0.0.1:$p http://'"$IP_ECHO"':8080/ >/dev/null 2>&1; then echo ok; else echo fail; fi >> /tmp/upd-$p.out; sleep 0.5; done) & done; wait'
started=$SECONDS
if waitfor 240 "the automatic update" "[ \"\$(host_field outcome)\" = on_target ] && [ \"\$(host_field state)\" = updated ]"; then
  echo "PASS the host moved to $V2 by itself ($((SECONDS - started))s after the release became available to it)"
else echo "FAIL automatic update: outcome $(host_field outcome), state $(host_field state), error $(host_field error)"; status=1; fi
check "the heartbeat reports agent_version $V2, previous $V1" "[ \"\$(host_field agent_version)\" = $V2 ] && [ \"\$(host_field previous_version)\" = $V1 ]"
check "$V2 is the installed binary; $V1 is kept as .previous" \
  "[ \"\$(running_version)\" = $V2 ] && [ \"\$(docker exec ccx-exit /opt/ccproxy-exit/bin/ccproxy-exit-agent.previous version | awk '{print \$2}')\" = $V1 ]"
check "systemd restarted the agent once (exit 75, Restart=always)" "[ \"\$(agent_restarts)\" = $((RESTARTS + 1)) ]"
check "the new agent confirmed itself healthy and adopted sing-box's config without a reload" \
  "agent_logged 'update: agent-e2e-v2 (sequence 2) confirmed healthy' && agent_logged 'adopted it without a reload'"
check "sing-box and frpc were not restarted (MainPIDs unchanged)" "[ \"\$(unit_pid ccproxy-exit-singbox)\" = '$SB_PID' ] && [ \"\$(unit_pid ccproxy-exit-frpc)\" = '$FRPC_PID' ]"
check "both XTCP ports are still ready" "[ \"\$(port_status)\" = '20443=ready 20444=ready' ] && [ \"\$(sync_state)\" = ready ]"
check "enrollment and configuration are untouched (token, install.conf, frpc.toml)" \
  "docker exec ccx-exit sh -c 'test -s /etc/ccproxy-exit/agent.token && grep -q \"AGENT_VERSION=.$V1.\" /etc/ccproxy-exit/install.conf && grep -q ccproxy-208-direct-20444 /etc/ccproxy-exit/frpc.toml'"
docker exec ccx-visitor touch /tmp/upd.stop
sleep 2
for p in 2080 2081 2082; do
  docker exec ccx-visitor cat /tmp/upd-$p.out > "$OUT/update-probe-$p.txt"
  echo "during the update, port $p: $(grep -c ok "$OUT/update-probe-$p.txt") ok, $(grep -c fail "$OUT/update-probe-$p.txt") failed"
done
check "alice (XTCP), bob (XTCP, second port) and alice (Direct) were never interrupted by the update" \
  "! grep -q fail '$OUT/update-probe-2080.txt' '$OUT/update-probe-2081.txt' '$OUT/update-probe-2082.txt' && grep -q ok '$OUT/update-probe-2080.txt' && grep -q ok '$OUT/update-probe-2081.txt' && grep -q ok '$OUT/update-probe-2082.txt'"

echo "== rollback rehearsal: $V3's agent exits right after starting"
api PUT /admin/agent-rollout "{\"version\":\"$V3\",\"hosts\":[\"macmini-sg-208\"]}" >/dev/null
started=$SECONDS
if waitfor 300 "the rollback" "[ \"\$(host_field state)\" = rolled_back ] && [ \"\$(host_field target_version)\" = $V3 ]"; then
  echo "PASS $V3 was rolled back to $V2 ($((SECONDS - started))s): $(host_field error)"
else echo "FAIL rollback: state $(host_field state), target $(host_field target_version)"; status=1; fi
check "the console shows the rollout failed for this host, running $V2" "[ \"\$(host_field outcome)\" = failed ] && [ \"\$(host_field agent_version)\" = $V2 ] && [ \"\$(running_version)\" = $V2 ]"
check "$V3 did start (and exited) before the rollback" "agent_logged 'broken test release: exiting at start' && agent_logged 'update: rolling back agent-e2e-v3-broken to agent-e2e-v2'"
check "after the rollback both ports are ready and sing-box and frpc kept running" \
  "[ \"\$(port_status)\" = '20443=ready 20444=ready' ] && [ \"\$(unit_pid ccproxy-exit-singbox)\" = '$SB_PID' ] && [ \"\$(unit_pid ccproxy-exit-frpc)\" = '$FRPC_PID' ]"
check "alice and bob (XTCP) and alice (Direct) still leave from $IP_EXIT" "[ \"\$(via 2080)\" = $IP_EXIT ] && [ \"\$(via 2081)\" = $IP_EXIT ] && [ \"\$(via 2082)\" = $IP_EXIT ]"
sleep 15
check "$V2 stays: the rolled-back release is not retried for the same rollout" "[ \"\$(running_version)\" = $V2 ] && [ \"\$(host_field state)\" = rolled_back ]"
api DELETE /admin/agent-rollout >/dev/null
docker exec ccx-visitor sh -c 'pkill -f bob-visitor.toml; pkill -f bob-client.json; pkill -f direct-client.json' || true

echo "== failed hole punching closes the connection (no relay)"
docker exec ccx-exit sh -c "iptables -I INPUT -p udp -s $IP_VISITOR -j DROP && iptables -I OUTPUT -p udp -d $IP_VISITOR -j DROP"
docker exec ccx-visitor sh -c 'pkill frpc; sleep 1; frpc -c /etc/visitor.toml > /tmp/visitor-blocked.log 2>&1 &'
sleep 2
before=$(frps_bytes)
start=$SECONDS
if proxied -o /dev/null "http://$IP_ECHO:8080/big"; then blocked_ok=0; else blocked_ok=1; fi
after=$(frps_bytes)
echo "blocked: request failed=$blocked_ok after $((SECONDS - start))s; frps moved $((after - before)) bytes"
check "with UDP blocked the proxied request fails" "[ $blocked_ok = 1 ]"
check "and nothing was relayed through frps" "[ $((after - before)) -lt 1048576 ]"
docker cp ccx-visitor:/tmp/visitor-blocked.log "$OUT/" >/dev/null
grep -Ei 'error|timeout|fail' "$OUT/visitor-blocked.log" | sed 's/^/  visitor: /' | head -5
check "the visitor reported the failed tunnel" "grep -Eqi 'error|timeout' '$OUT/visitor-blocked.log'"
docker exec ccx-exit sh -c "iptables -D INPUT -p udp -s $IP_VISITOR -j DROP && iptables -D OUTPUT -p udp -d $IP_VISITOR -j DROP"

echo "== reboot: services start without a login and the tunnel comes back"
docker restart ccx-exit >/dev/null
for unit in ccproxy-exit-agent ccproxy-exit-singbox ccproxy-exit-frpc; do
  waitfor 90 "$unit after reboot" "docker exec ccx-exit systemctl is-active --quiet $unit 2>/dev/null"
done
echo "PASS services active after reboot"
if waitfor 90 "XTCP sync after reboot" "[ \"\$(sync_state)\" = ready ]"; then echo "PASS XTCP sync is ready after the reboot"
else echo "FAIL XTCP sync after reboot: $(sync_state)"; status=1; fi
docker exec ccx-visitor sh -c 'pkill frpc; sleep 1; frpc -c /etc/visitor.toml > /tmp/visitor.log 2>&1 &'
waitfor 120 "tunnel after reboot" "[ \"\$(proxied http://$IP_ECHO:8080/ 2>/dev/null)\" = '$IP_EXIT' ]" && echo "PASS proxied IPv4 after reboot is $IP_EXIT" || { echo "FAIL tunnel after reboot"; status=1; }

echo "== uninstall"
UNCMD=$(api GET "/admin/install-commands?cp=https://cp:8443" | json '["linux"]["uninstall"]')
docker exec ccx-exit sh -c "$UNCMD" > "$OUT/uninstall.log" 2>&1
check "uninstall removed services, files and credentials" "! docker exec ccx-exit sh -c 'ls /etc/systemd/system/ccproxy-exit-* /opt/ccproxy-exit /etc/ccproxy-exit 2>/dev/null' | grep -q ."

[ $status = 0 ] && echo "ALL PASSED" || echo "SOME CHECKS FAILED"
exit $status
