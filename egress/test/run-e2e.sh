#!/usr/bin/env bash
# End-to-end test of the egress prototype in Docker.
#   1. per-device egress IP (exclusive and shared), domain targets, UDP
#   2. users without an IP, revoked devices and blocked destinations get no egress
#   3. TUN clients: domain mode (fake-IP, default route untouched) and app mode (split by process)
#   4. hot reload (SIGHUP) applies binding changes and revocations
# KEEP=1 leaves the containers running afterwards.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GEN="$HERE/../gen.py"
OUT="$HERE/out"
IMAGE="ghcr.io/sagernet/sing-box:v1.14.4"
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }

rm -rf "$OUT" && mkdir -p "$OUT/egress" "$OUT/clients" "$OUT/tun"

echo "== generate keys and inventory"
keys="$(docker run --rm "$IMAGE" generate reality-keypair)"
priv="$(awk '/PrivateKey/ {print $2}' <<<"$keys")"
pub="$(awk '/PublicKey/ {print $2}' <<<"$keys")"
python3 - "$HERE/inventory.template.json" "$OUT/inventory.json" "$priv" "$pub" <<'PY'
import secrets, sys, uuid
src, dst, priv, pub = sys.argv[1:]
text = open(src).read().replace("@PRIVATE_KEY@", priv).replace("@PUBLIC_KEY@", pub)
text = text.replace("@SHORT_ID@", secrets.token_hex(8))
while "@UUID@" in text:
    text = text.replace("@UUID@", str(uuid.uuid4()), 1)
open(dst, "w").write(text)
PY

render() {
  python3 "$GEN" server "$OUT/inventory.json" -o "$OUT/egress/server.json"
  python3 "$GEN" ips "$OUT/inventory.json" > "$OUT/egress/ips.txt"
}
render
port=2081
for dev in alice-mac alice-win bob-mac carol-mac dave-mac erin-mac frank-old frank-new; do
  python3 "$GEN" client "$OUT/inventory.json" "$dev" --listen 0.0.0.0 --port "$port" --allow-revoked \
    -o "$OUT/clients/$dev.json"
  port=$((port + 1))
done
python3 "$GEN" client "$OUT/inventory.json" alice-mac --mode domain -o "$OUT/tun/domain.json"
python3 "$GEN" client "$OUT/inventory.json" bob-mac --mode app -o "$OUT/tun/app.json"

echo "== sing-box check"
for f in egress/server.json clients/alice-mac.json tun/domain.json tun/app.json; do
  docker run --rm -v "$OUT:/out:ro" "$IMAGE" check -c "/out/$f"
done
echo "configs ok"

cleanup() {
  if [[ "${KEEP:-0}" != 1 ]]; then compose down -v --remove-orphans >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "== start containers"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --build --wait 2>&1 | tail -n 3 || compose up -d
for _ in $(seq 1 30); do
  compose exec -T probe python -c "import socket; socket.create_connection(('clients', 2088), 1)" 2>/dev/null && break
  sleep 1
done
compose logs egress | grep -E 'inet |started|FATAL|ERROR' || true

status=0
echo "== phase 1: initial bindings"
compose exec -T probe python /app/probe.py initial || status=1

echo "== phase 1b: TUN clients (domain mode, app mode)"
compose exec -T tun-domain python3 /app/client_probe.py domain || status=1
compose exec -T tun-app python3 /app/client_probe.py app-other || status=1
compose exec -T tun-app tunapp /app/client_probe.py app-selected || status=1

echo "== phase 2: change bindings and reload with SIGHUP"
python3 - "$OUT/inventory.json" <<'PY'
import json, sys
path = sys.argv[1]
inv = json.load(open(path))
for e in inv["egress_ips"]:
    if e["ip"] == "10.99.0.7":
        e["status"] = "available"
users = {u["name"]: u for u in inv["users"]}
users["bob"].pop("egress_ip")
users["erin"]["egress_ip"] = "10.99.0.7"
for d in users["alice"]["devices"]:
    if d["name"] == "alice-win":
        d["revoked"] = True
json.dump(inv, open(path, "w"), indent=2)
PY
render
docker run --rm -v "$OUT:/out:ro" "$IMAGE" check -c /out/egress/server.json
compose kill -s HUP egress >/dev/null
sleep 3
compose exec -T probe python /app/probe.py reloaded || status=1

echo "== egress log (tail)"
compose logs --no-log-prefix egress | tail -n 12

if [[ $status -eq 0 ]]; then echo "E2E PASS"; else echo "E2E FAIL"; fi
exit $status
