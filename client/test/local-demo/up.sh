#!/usr/bin/env bash
# Start a local control plane plus a Docker exit node, and create a demo account for the desktop app.
#   client/test/local-demo/up.sh        prints the server address, username and password
#   client/test/local-demo/down.sh      stops everything
# DIRECT_DNS: resolver for names outside the rules (default: this Mac's first DNS server).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="$HERE/out"
CP="http://127.0.0.1:18450"
mkdir -p "$OUT"
export CP_ADMIN_TOKEN="${CP_ADMIN_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(16))')}"
cpctl() { CP_URL="$CP" python3 "$ROOT/controlplane/cpctl.py" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

dns="${DIRECT_DNS:-$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/ {print $3; exit}')}"
dns="${dns:-1.1.1.1}"

rm -f "$OUT"/cp.db*
cat > "$OUT/settings.json" <<JSON
{"client_policy": {"domain_suffix": ["echo.example.com"], "direct_dns": "$dns"}}
JSON
admin_pw=$(python3 "$ROOT/controlplane/server.py" init --db "$OUT/cp.db" --settings "$OUT/settings.json" --admin admin |
  awk '/console admin/ {print $5}')
CP_ADMIN_TOKEN="$CP_ADMIN_TOKEN" nohup python3 "$ROOT/controlplane/server.py" serve --db "$OUT/cp.db" \
  --listen 127.0.0.1 --port 18450 > "$OUT/cp.log" 2>&1 &
echo $! > "$OUT/cp.pid"
for _ in $(seq 1 20); do curl -fs "$CP/healthz" >/dev/null && break; sleep 0.5; done

AGENT_TOKEN=$(cpctl host-add local 127.0.0.1 decoy.test --handshake 10.99.0.20 --ports 20000-20009 \
  --allow-private --block-cidr 169.254.169.254/32 | field '["agent_token"]')
cpctl ip-add local 10.99.0.3 >/dev/null
password=$(cpctl user-add demo | field '["password"]')
cpctl assign demo >/dev/null
echo "$CP_ADMIN_TOKEN" > "$OUT/admin-token"

AGENT_TOKEN="$AGENT_TOKEN" docker compose -f "$HERE/compose.yaml" up -d --build 2>&1 | tail -n 1
for _ in $(seq 1 30); do
  docker compose -f "$HERE/compose.yaml" logs egress 2>/dev/null | grep 'started sing-box' >/dev/null && break; sleep 1
done

cat <<EOF

控制端地址  $CP
用户名      demo
密码        $password
规则域名    echo.example.com（连接后 curl http://echo.example.com:8080 应返回 10.99.0.3；不用 .test，macOS 会在本地拒绝解析它）
其他域名    用 $dns 直连解析
管理后台    $CP/   管理员 admin，密码 $admin_pw
EOF
