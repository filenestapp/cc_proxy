#!/usr/bin/env bash
# Start the Docker control plane and exit node, and create a demo account for the desktop app.
#   client/test/local-demo/up.sh        prints the server address, username and password
#   client/test/local-demo/down.sh      stops everything
# DIRECT_DNS: resolver for names outside the rules (default: this Mac's first DNS server).
# CP_DEMO_PORT: host port for the control plane (default: 18450).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="$HERE/out"
CP="http://127.0.0.1:${CP_DEMO_PORT:-18450}"
mkdir -p "$OUT"
export CP_ADMIN_TOKEN="${CP_ADMIN_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(16))')}"
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }
cpctl() { CP_URL="$CP" python3 "$ROOT/controlplane/cpctl.py" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

dns="${DIRECT_DNS:-$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/ {print $3; exit}')}"
dns="${dns:-1.1.1.1}"

cat > "$OUT/settings.json" <<JSON
{"client_policy": {"domain_suffix": ["echo.example.com"], "direct_dns": "$dns"}}
JSON
compose down -v --remove-orphans
compose up -d --wait db
compose build cp
admin_pw=$(compose run --rm -T --no-deps cp init --settings /out/settings.json --admin admin |
  awk '/console admin/ {print $5}')
compose up -d --wait cp

AGENT_TOKEN=$(cpctl host-add local 127.0.0.1 decoy.test --handshake 10.99.0.20 --ports 20000-20009 \
  --allow-private --block-cidr 169.254.169.254/32 | field '["agent_token"]')
cpctl ip-add local 10.99.0.3 >/dev/null
password=$(cpctl user-add demo | field '["password"]')
cpctl assign demo >/dev/null
echo "$CP_ADMIN_TOKEN" > "$OUT/admin-token"

AGENT_TOKEN="$AGENT_TOKEN" compose up -d --build egress
for _ in $(seq 1 30); do
  compose logs egress 2>/dev/null | grep 'started sing-box' >/dev/null && break; sleep 1
done

cat <<EOF

Control plane  $CP
Username       demo
Password       $password
Proxied domain echo.example.com (after connecting, curl http://echo.example.com:8080 should return 10.99.0.3)
Direct DNS     $dns
Admin console  $CP/ (username admin, password $admin_pw)
EOF
