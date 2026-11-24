#!/usr/bin/env bash
# Shared egress IP e2e: several users on one egress IPv4 with distinct entry ports, through real sing-box and frp.
#
#   cp        this checkout's control plane, built and run on this machine against its own schema in
#             TEST_DATABASE_URL (plain HTTP on 127.0.0.1)
#   exit-pub  host "pub" on the public-entry transport: sing-box server from /agent/server-config
#   exit-nat  host "nat" on XTCP: sing-box server plus frpc from /install/xtcp/frpc.toml
#   frps      official frps 0.72.0 on TCP 7003 (TLS with a test CA, token auth; rendezvous only)
#   c-alice, c-bob      sing-box clients built from each user's /v1/config?mode=proxy (direct entry)
#   v-carol, v-dave     an frpc XTCP visitor plus a sing-box client per user (XTCP entry)
#   echo      answers with the caller's IPv4
#
# Checks: two shared users on the direct host and two on the XTCP host reach their own listener and leave from the
# same egress IPv4, concurrently; an existing single-port XTCP host upgrades without touching the first mapping or its
# visitor; a user's visitor key opens only that user's proxy; allocation conflicts and mode switches; releasing or
# revoking one holder leaves the other working.
#
# Needs: Docker, Go, psql, TEST_DATABASE_URL, internet access (pinned binaries from GitHub, Reality handshake
# target, STUN for frp hole punching). KEEP=1 leaves the containers running.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="${OUT:-$HERE/out}"
: "${TEST_DATABASE_URL:?set TEST_DATABASE_URL to a PostgreSQL database for test schemas}"
NET=ccs-e2e
SUBNET=172.31.92.0/24
IP_FRPS=172.31.92.10 IP_PUB=172.31.92.21 IP_NAT=172.31.92.22 IP_ECHO=172.31.92.40
FRP_VERSION=0.72.0
SINGBOX_VERSION=1.14.4
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
rnd() { openssl rand -hex 24; }
ADMIN_TOKEN="admin-$(rnd)" FRPS_TOKEN="frps-$(rnd)" XTCP_KEY="xtcp-$(rnd)" PW="user-password-0123"
SCHEMA="cp_shared_e2e_$(openssl rand -hex 6)"
CP_PORT="${CP_PORT:-18493}"
CP="http://127.0.0.1:$CP_PORT"
CONTAINERS="ccs-frps ccs-exit-pub ccs-exit-nat ccs-echo ccs-c-alice ccs-c-bob ccs-v-carol ccs-v-dave"
CP_PID=""

psql_run() { psql -X -wqAt -v ON_ERROR_STOP=1 --dbname "$TEST_DATABASE_URL" -c "$1"; }
cleanup() {
  [ -n "$CP_PID" ] && kill "$CP_PID" 2>/dev/null || true
  for c in ccs-exit-pub ccs-exit-nat; do docker exec "$c" cat /tmp/sing-box.log > "$OUT/$c-sing-box.log" 2>/dev/null || true; done
  docker exec ccs-exit-nat cat /tmp/frpc.log > "$OUT/exit-nat-frpc.log" 2>/dev/null || true
  if [[ "${KEEP:-0}" != 1 ]]; then
    docker rm -f $CONTAINERS >/dev/null 2>&1 || true
    docker network rm $NET >/dev/null 2>&1 || true
    psql_run "DROP SCHEMA IF EXISTS $SCHEMA CASCADE" >/dev/null 2>&1 || true
    rm -rf "$OUT/tls" "$OUT/frps.toml" "$OUT"/*.toml "$OUT"/*.json "$OUT/tokens"   # test credentials
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
json() { python3 -I -c "import json,sys; print(json.load(sys.stdin)$1)"; }

docker rm -f $CONTAINERS >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
rm -rf "$OUT" && mkdir -p "$OUT/tls" "$OUT/bin" "$OUT/tokens"
chmod 700 "$OUT"

echo "== build: control plane, tools image"
(cd "$REPO/controlplane" && go build -o "$OUT/cc-controlplane" .)
if ! docker image inspect ccx-tools >/dev/null 2>&1; then
  docker build -q -t ccx-tools - >/dev/null <<'EOF'
FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates python3 procps >/dev/null \
 && rm -rf /var/lib/apt/lists/*
EOF
fi

echo "== frp $FRP_VERSION and sing-box $SINGBOX_VERSION (checked against the installer's pins)"
pin() { python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['assets'][sys.argv[2]][sys.argv[3]])" "$@"; }
fetch() { # fetch PINS_FILE URL_PREFIX DEST_DIR
  local file sha; file=$(pin "$1" "linux-$ARCH" file); sha=$(pin "$1" "linux-$ARCH" sha256)
  if [ -n "${BIN_CACHE:-}" ] && [ -f "$BIN_CACHE/$file" ]; then cp "$BIN_CACHE/$file" "$3/$file"
  else curl -q --proto '=https' --proto-redir '=https' -fsSL -o "$3/$file" "$2/$file"; fi
  echo "$sha  $3/$file" | shasum -a 256 -c - >/dev/null
  tar -xzf "$3/$file" -C "$3"
}
fetch "$REPO/controlplane/install/frpc.json" "https://github.com/fatedier/frp/releases/download/v$FRP_VERSION" "$OUT/bin"
fetch "$REPO/controlplane/install/sing-box.json" "https://github.com/SagerNet/sing-box/releases/download/v$SINGBOX_VERSION" "$OUT/bin"
FRP_DIR="$OUT/bin/frp_${FRP_VERSION}_linux_$ARCH"
SB_BIN="$OUT/bin/sing-box-$SINGBOX_VERSION-linux-$ARCH/sing-box"

echo "== test CA and frps certificate"
(
  cd "$OUT/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 2 \
    -subj "/CN=CC Proxy shared egress e2e CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=keyCertSign" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout frps.key -out frps.csr -subj "/CN=frps" 2>/dev/null
  printf 'subjectAltName=DNS:frps\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > frps.ext
  openssl x509 -req -in frps.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out frps.pem -days 2 -extfile frps.ext 2>/dev/null
  chmod 644 ./*.pem ./*.key
)

echo "== control plane on $CP (schema $SCHEMA)"
psql_run "CREATE SCHEMA $SCHEMA"
DSN=$(python3 -I -c "import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1]); q=dict(u.parse_qsl(p.query), search_path=sys.argv[2]); print(u.urlunsplit(p._replace(query=u.urlencode(q))))" "$TEST_DATABASE_URL" "$SCHEMA")
DATABASE_URL="$DSN" "$OUT/cc-controlplane" init >/dev/null
DATABASE_URL="$DSN" CP_ADMIN_TOKEN="$ADMIN_TOKEN" "$OUT/cc-controlplane" serve --listen 127.0.0.1 --port "$CP_PORT" > "$OUT/cp.log" 2>&1 &
CP_PID=$!
waitfor 30 "control plane" "curl -fsS $CP/healthz >/dev/null 2>&1"
api() { # api METHOD PATH [JSON] -> body; HTTP status in $OUT/status
  curl -q -sS -o "$OUT/body" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$CP$2" > "$OUT/status"
  cat "$OUT/body"
}
code() { cat "$OUT/status"; }
login() { # login USER DEVICE -> device token
  curl -q -sS -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$PW\",\"device\":\"$2\"}" "$CP/v1/login" | json '["token"]'
}
client_config() { curl -q -sS -H "Authorization: Bearer $1" "$CP/v1/config?mode=proxy"; }
agent_get() { curl -q -sS -H "Authorization: Bearer $1" "$CP$2"; }

echo "== containers"
docker network create --subnet $SUBNET $NET >/dev/null
cat > "$OUT/echo.py" <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.client_address[0] + "\n").encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
cat > "$OUT/frps.toml" <<EOF
bindPort = 7003
auth.method = "token"
auth.token = "$FRPS_TOKEN"
transport.tls.force = true
transport.tls.certFile = "/tls/frps.pem"
transport.tls.keyFile = "/tls/frps.key"
log.to = "console"
EOF
run() { # run NAME IP [docker args...] -- a long-running tools container with sing-box and frp mounted
  local name=$1 ip=$2; shift 2
  docker run -d --name "$name" --network $NET --ip "$ip" -v "$OUT/tls:/tls:ro" -v "$SB_BIN:/usr/local/bin/sing-box:ro" \
    -v "$FRP_DIR/frpc:/usr/local/bin/frpc:ro" -v "$FRP_DIR/frps:/usr/local/bin/frps:ro" "$@" ccx-tools sleep infinity >/dev/null
}
run ccs-frps $IP_FRPS --network-alias frps -v "$OUT/frps.toml:/etc/frps.toml:ro"
docker exec -d ccs-frps sh -c 'frps -c /etc/frps.toml > /tmp/frps.log 2>&1'
run ccs-echo $IP_ECHO -v "$OUT/echo.py:/echo.py:ro"
docker exec -d ccs-echo python3 /echo.py
run ccs-exit-pub $IP_PUB
run ccs-exit-nat $IP_NAT
run ccs-c-alice 172.31.92.31
run ccs-c-bob 172.31.92.32
run ccs-v-carol 172.31.92.33
run ccs-v-dave 172.31.92.34

start_server() { # start_server CONTAINER AGENT_TOKEN: fetch /agent/server-config and (re)start sing-box with it
  agent_get "$2" /agent/server-config > "$OUT/$1-server.json"
  docker cp "$OUT/$1-server.json" "$1:/etc/server.json" >/dev/null
  docker exec "$1" sh -c 'pkill -x sing-box; sleep 0.5; sing-box check -c /etc/server.json && (sing-box run -c /etc/server.json >> /tmp/sing-box.log 2>&1 &)'
}
start_client() { # start_client CONTAINER DEVICE_TOKEN: a sing-box client from the user's own config
  client_config "$2" > "$OUT/$1-client.json"
  docker cp "$OUT/$1-client.json" "$1:/etc/client.json" >/dev/null
  docker exec "$1" sh -c 'pkill -x sing-box; sleep 0.5; (sing-box run -c /etc/client.json > /tmp/client.log 2>&1 &)'
}
seen() { docker exec "$1" curl -q -sS --max-time 20 -x socks5h://127.0.0.1:2080 "http://$IP_ECHO:8080/" 2>/dev/null; }
concurrently() { # concurrently C1 OUT1 C2 OUT2: two users' requests at the same time (not waiting on the cp job)
  seen "$1" > "$2" & local p1=$!
  seen "$3" > "$4" & local p2=$!
  wait "$p1" "$p2" || true
}
host_body='"server_name":"www.cloudflare.com","port_min":20000,"port_max":20999,"block_private":false,"block_cidrs":["169.254.169.254/32"]'

echo "== direct host: alice exclusive, then switched to shared; bob joins the same IPv4"
PUB_TOKEN=$(api POST /admin/hosts "{\"name\":\"pub\",\"public_host\":\"$IP_PUB\",$host_body}" | json '["agent_token"]')
api POST /admin/hosts/pub/ips "{\"ips\":[\"$IP_PUB\"]}" >/dev/null
for u in alice bob eve; do api POST /admin/users "{\"name\":\"$u\",\"password\":\"$PW\"}" >/dev/null; done
api POST /admin/users/alice/assign "{\"ip\":\"$IP_PUB\",\"port\":20007}" >/dev/null
ALICE=$(login alice laptop)
client_config "$ALICE" > "$OUT/alice-before.json"
api POST /admin/users/bob/assign "{\"ip\":\"$IP_PUB\"}" > "$OUT/r.json"
check "an exclusive holder refuses a second user (409, names the holder)" "[ \$(code) = 409 ] && grep -q 'alice (exclusive)' '$OUT/r.json'"
api PUT /admin/users/bob '{"mode":"shared"}' >/dev/null
api PUT /admin/users/alice '{"mode":"shared"}' >/dev/null
check "switching alice to shared succeeds" "[ \$(code) = 200 ]"
client_config "$ALICE" > "$OUT/alice-after.json"
check "alice's client config (IP, port, UUID) is unchanged by the switch" "cmp -s '$OUT/alice-before.json' '$OUT/alice-after.json'"
api POST /admin/users/bob/assign "{\"ip\":\"$IP_PUB\",\"port\":20007}" > "$OUT/r.json"
check "a taken entry port is refused (409)" "[ \$(code) = 409 ] && grep -q 'used by alice' '$OUT/r.json'"
api POST /admin/users/bob/assign "{\"ip\":\"$IP_PUB\"}" > "$OUT/r.json"
check "bob shares alice's IPv4 on the lowest free port" "[ \$(code) = 200 ] && [ \"\$(json '[\"port\"]' < '$OUT/r.json')\" = 20000 ]"
api POST /admin/users/eve/assign "{\"ip\":\"$IP_PUB\"}" > "$OUT/r.json"
check "an exclusive user cannot join a shared IPv4 (409)" "[ \$(code) = 409 ]"
api PUT /admin/users/alice '{"mode":"exclusive"}' > "$OUT/r.json"
check "alice cannot go back to exclusive while bob shares (409)" "[ \$(code) = 409 ] && grep -q bob '$OUT/r.json'"
api GET "/admin/ips?host=pub" > "$OUT/ips.json"
check "the IP view lists both holders with their ports" \
  "python3 -I -c \"import json,sys; h=json.load(open(sys.argv[1]))[0]['holders']; sys.exit(0 if [(x['user'],x['port']) for x in h]==[('bob',20000),('alice',20007)] else 1)\" '$OUT/ips.json'"
api GET /admin/hosts > "$OUT/hosts.json"
check "the host view shows the entry capacity" "python3 -I -c \"import json,sys; h=json.load(open(sys.argv[1]))[0]; sys.exit(0 if (h['port_capacity'],h['free_ports'])==(1000,998) else 1)\" '$OUT/hosts.json'"
BOB=$(login bob laptop)
start_server ccs-exit-pub "$PUB_TOKEN"
start_client ccs-c-alice "$ALICE"
start_client ccs-c-bob "$BOB"
waitfor 60 "alice through pub" "[ -n \"\$(seen ccs-c-alice)\" ]"
concurrently ccs-c-alice "$OUT/a.txt" ccs-c-bob "$OUT/b.txt"
echo "concurrent: alice saw '$(cat "$OUT/a.txt")', bob saw '$(cat "$OUT/b.txt")'"
check "alice and bob, concurrently, both leave from $IP_PUB" "[ \"\$(cat '$OUT/a.txt')\" = $IP_PUB ] && [ \"\$(cat '$OUT/b.txt')\" = $IP_PUB ]"
check "each reached its own listener (user-alice on 20007, user-bob on 20000)" \
  "docker exec ccs-exit-pub grep -q 'inbound/vless\[user-alice\]' /tmp/sing-box.log && docker exec ccs-exit-pub grep -q 'inbound/vless\[user-bob\]' /tmp/sing-box.log"
api POST /admin/users/alice/devices/laptop/revoke >/dev/null
start_server ccs-exit-pub "$PUB_TOKEN"
sleep 2
check "after alice's device is revoked, bob still connects" "[ \"\$(seen ccs-c-bob)\" = $IP_PUB ]"
check "and alice no longer does" "[ -z \"\$(seen ccs-c-alice)\" ]"

echo "== XTCP host: an existing single-port host (carol on 20443) upgraded with a second shared user (dave)"
NAT_TOKEN=$(api POST /admin/hosts "{\"name\":\"nat\",\"public_host\":\"127.0.0.1\",$host_body}" | json '["agent_token"]')
api POST /admin/hosts/nat/ips "{\"ips\":[\"$IP_NAT\"]}" >/dev/null
for u in carol dave; do api POST /admin/users "{\"name\":\"$u\",\"password\":\"$PW\"}" >/dev/null; done
api POST /admin/users/carol/assign "{\"ip\":\"$IP_NAT\",\"port\":20443}" >/dev/null
CA_JSON=$(python3 -I -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$OUT/tls/ca.pem")
api PUT /admin/hosts/nat/xtcp "{\"server_addr\":\"$IP_FRPS\",\"server_port\":7003,\"tls_server_name\":\"frps\",\"ca_pem\":$CA_JSON,\"auth_token\":\"$FRPS_TOKEN\",\"proxy_name\":\"ccproxy-nat-direct\",\"secret_key\":\"$XTCP_KEY\",\"local_port\":20443}" > "$OUT/xtcp.json"
check "the admin XTCP view hides both secrets" "! grep -q -e '$FRPS_TOKEN' -e '$XTCP_KEY' '$OUT/xtcp.json'"
start_frpc() { # fetch the host's frpc.toml as the installer does and (re)start frpc
  agent_get "$NAT_TOKEN" "/install/xtcp/frpc.toml?ca_file=/tls/ca.pem" > "$OUT/$1"
  docker cp "$OUT/$1" ccs-exit-nat:/etc/frpc.toml >/dev/null
  docker exec ccs-exit-nat sh -c 'frpc verify -c /etc/frpc.toml >/dev/null && pkill -x frpc; sleep 0.5; (frpc -c /etc/frpc.toml >> /tmp/frpc.log 2>&1 &)'
}
CAROL=$(login carol macbook)
start_frpc frpc-v1.toml
start_server ccs-exit-nat "$NAT_TOKEN"
check "the single-port frpc configuration has one proxy" "[ \$(grep -c '^\[\[proxies\]\]' '$OUT/frpc-v1.toml') = 1 ]"
# carol's existing visitor, written by hand before this release, with the host secret key.
cat > "$OUT/carol-legacy.toml" <<EOF
serverAddr = "$IP_FRPS"
serverPort = 7003
auth.method = "token"
auth.token = "$FRPS_TOKEN"
transport.tls.enable = true
transport.tls.trustedCaFile = "/tls/ca.pem"
transport.tls.serverName = "frps"

[[visitors]]
name = "ccproxy-nat-visitor"
type = "xtcp"
serverName = "ccproxy-nat-direct"
secretKey = "$XTCP_KEY"
bindAddr = "127.0.0.1"
bindPort = 20443
protocol = "quic"
EOF
docker cp "$OUT/carol-legacy.toml" ccs-v-carol:/etc/visitor.toml >/dev/null
docker exec ccs-v-carol sh -c '(frpc -c /etc/visitor.toml > /tmp/visitor.log 2>&1 &)'
start_client ccs-v-carol "$CAROL"
if waitfor 90 "carol through XTCP" "[ \"\$(seen ccs-v-carol)\" = $IP_NAT ]"; then echo "PASS carol (single-port host) leaves from $IP_NAT"
else echo "FAIL carol (single-port host) through XTCP"; status=1; fi

api PUT /admin/users/carol '{"mode":"shared"}' >/dev/null
api PUT /admin/users/dave '{"mode":"shared"}' >/dev/null
api POST /admin/users/dave/assign "{\"ip\":\"$IP_NAT\"}" > "$OUT/r.json"
check "dave shares carol's IPv4 on entry port 20000" "[ \$(code) = 200 ] && [ \"\$(json '[\"port\"]' < '$OUT/r.json')\" = 20000 ]"
check "the console reports the installed frpc as outdated" "[ \"\$(api GET /admin/hosts/nat/xtcp | json '[\"frpc_state\"]')\" = outdated ]"
DAVE=$(login dave laptop)
start_frpc frpc-v2.toml
check "the upgraded frpc configuration keeps the first mapping byte for byte" \
  "python3 -I -c \"import sys; a=open(sys.argv[1]).read(); b=open(sys.argv[2]).read(); sys.exit(0 if b.startswith(a) and b.count('[[proxies]]')==2 else 1)\" '$OUT/frpc-v1.toml' '$OUT/frpc-v2.toml'"
check "and the console reports it current" "[ \"\$(api GET /admin/hosts/nat/xtcp | json '[\"frpc_state\"]')\" = current ]"
start_server ccs-exit-nat "$NAT_TOKEN"
api GET "/admin/users/dave/xtcp-visitor?ca_file=/tls/ca.pem" > "$OUT/dave-visitor.json"
json '["frpc_toml"]' < "$OUT/dave-visitor.json" > "$OUT/dave-visitor.toml"
check "dave's visitor holds neither the frps token nor the host secret key" "! grep -q -e '$FRPS_TOKEN' -e '$XTCP_KEY' '$OUT/dave-visitor.toml'"
docker cp "$OUT/dave-visitor.toml" ccs-v-dave:/etc/visitor.toml >/dev/null
docker exec -e FRP_AUTH_TOKEN="$FRPS_TOKEN" ccs-v-dave sh -c 'frpc verify -c /etc/visitor.toml >/dev/null && (frpc -c /etc/visitor.toml > /tmp/visitor.log 2>&1 &)'
start_client ccs-v-dave "$DAVE"
if waitfor 90 "dave through XTCP" "[ \"\$(seen ccs-v-dave)\" = $IP_NAT ]"; then echo "PASS dave (new mapping) leaves from $IP_NAT"
else echo "FAIL dave through XTCP"; status=1; fi
if waitfor 90 "carol after the frpc restart" "[ \"\$(seen ccs-v-carol)\" = $IP_NAT ]"; then echo "PASS carol (original visitor) leaves from $IP_NAT after the upgrade"
else echo "FAIL carol after the upgrade"; status=1; fi
concurrently ccs-v-carol "$OUT/c.txt" ccs-v-dave "$OUT/d.txt"
echo "concurrent: carol saw '$(cat "$OUT/c.txt")', dave saw '$(cat "$OUT/d.txt")'"
check "carol (original visitor) and dave (new mapping), concurrently, both leave from $IP_NAT" \
  "[ \"\$(cat '$OUT/c.txt')\" = $IP_NAT ] && [ \"\$(cat '$OUT/d.txt')\" = $IP_NAT ]"
check "each reached its own listener (user-carol on 20443, user-dave on 20000)" \
  "docker exec ccs-exit-nat grep -q 'inbound/vless\[user-carol\]' /tmp/sing-box.log && docker exec ccs-exit-nat grep -q 'inbound/vless\[user-dave\]' /tmp/sing-box.log"

echo "== scoping: dave's visitor key does not open carol's proxy"
sed -e 's/^serverName = .*/serverName = "ccproxy-nat-direct"/' -e 's/^bindPort = .*/bindPort = 21443/' -e 's/^name = .*/name = "probe-visitor"/' \
  "$OUT/dave-visitor.toml" > "$OUT/probe.toml"
python3 -I -c "import json,sys; c=json.load(open(sys.argv[1])); c['outbounds'][0]['server_port']=21443; c['inbounds'][0]['listen_port']=2081; json.dump(c,open(sys.argv[2],'w'))" \
  "$OUT/ccs-v-dave-client.json" "$OUT/probe-client.json"
docker cp "$OUT/probe.toml" ccs-v-dave:/etc/probe.toml >/dev/null
docker cp "$OUT/probe-client.json" ccs-v-dave:/etc/probe-client.json >/dev/null
docker exec -e FRP_AUTH_TOKEN="$FRPS_TOKEN" ccs-v-dave sh -c '(frpc -c /etc/probe.toml > /tmp/probe.log 2>&1 &); (sing-box run -c /etc/probe-client.json > /tmp/probe-client.log 2>&1 &)'
sleep 3
check "a request through carol's proxy with dave's key fails" \
  "! docker exec ccs-v-dave curl -q -sS --max-time 15 -x socks5h://127.0.0.1:2081 http://$IP_ECHO:8080/ >/dev/null 2>&1"
check "frps refused it as an authentication failure for carol's proxy" \
  "docker exec ccs-frps grep -q 'xtcp connection of \[ccproxy-nat-direct\] auth failed' /tmp/frps.log"

echo "== scoping: carol's primary (legacy) key does not open dave's proxy"
sed -e 's/^serverName = .*/serverName = "ccproxy-nat-direct-20000"/' -e 's/^bindPort = .*/bindPort = 21444/' -e 's/^name = .*/name = "probe-primary-visitor"/' \
  "$OUT/carol-legacy.toml" > "$OUT/probe-primary.toml"
python3 -I -c "import json,sys; c=json.load(open(sys.argv[1])); c['outbounds'][0]['server_port']=21444; c['inbounds'][0]['listen_port']=2082; json.dump(c,open(sys.argv[2],'w'))" \
  "$OUT/ccs-v-carol-client.json" "$OUT/probe-primary-client.json"
docker cp "$OUT/probe-primary.toml" ccs-v-carol:/etc/probe-primary.toml >/dev/null
docker cp "$OUT/probe-primary-client.json" ccs-v-carol:/etc/probe-primary-client.json >/dev/null
docker exec ccs-v-carol sh -c '(frpc -c /etc/probe-primary.toml > /tmp/probe-primary.log 2>&1 &); (sing-box run -c /etc/probe-primary-client.json > /tmp/probe-primary-client.log 2>&1 &)'
sleep 3
check "a request through dave's proxy with carol's primary key fails" \
  "! docker exec ccs-v-carol curl -q -sS --max-time 15 -x socks5h://127.0.0.1:2082 http://$IP_ECHO:8080/ >/dev/null 2>&1"
check "frps refused it as an authentication failure for dave's proxy" \
  "docker exec ccs-frps grep -q 'xtcp connection of \[ccproxy-nat-direct-20000\] auth failed' /tmp/frps.log"
check "carol's original visitor still works next to the failed probe" "[ \"\$(seen ccs-v-carol)\" = $IP_NAT ]"

echo "== release dave: carol keeps working"
api POST /admin/users/dave/release >/dev/null
check "releasing dave keeps the IP assigned to carol (no cooldown)" \
  "python3 -I -c \"import json,sys; i=json.load(sys.stdin)[0]; sys.exit(0 if i['status']=='assigned' and i['users']==['carol'] else 1)\" < <(api GET '/admin/ips?host=nat')"
start_frpc frpc-v3.toml
start_server ccs-exit-nat "$NAT_TOKEN"
check "the frpc configuration is back to the original single mapping" "cmp -s '$OUT/frpc-v1.toml' '$OUT/frpc-v3.toml'"
if waitfor 60 "carol after dave's release" "[ \"\$(seen ccs-v-carol)\" = $IP_NAT ]"; then echo "PASS carol still leaves from $IP_NAT"
else echo "FAIL carol after dave's release"; status=1; fi

[ $status = 0 ] && echo "ALL PASSED" || echo "SOME CHECKS FAILED"
exit $status
