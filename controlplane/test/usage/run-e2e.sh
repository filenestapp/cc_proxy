#!/usr/bin/env bash
# Per-device usage e2e against real sing-box (see driver.py for the phases).
#   The exit runs the pinned linux installer package from controlplane/install/sing-box.json, verified by SHA-256
#   (downloaded once into .cache/, or taken from SINGBOX_ASSET_DIR). Clients run the official sing-box image.
#   exit-jp runs the agent from OLD_AGENT_REF (default: the release before usage collection).
# KEEP=1 leaves the containers running.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="$HERE/out"
CACHE="$HERE/.cache"
OLD_AGENT_REF="${OLD_AGENT_REF:-3f4acd38f8006eb4510aba4de983b06008852ea7}"
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }

case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "unsupported Docker architecture" >&2; exit 1 ;;
esac

export CP_ADMIN_TOKEN="admin-$(openssl rand -hex 16)" HK_TOKEN="" JP_TOKEN=""
cleanup() {
  if [[ "${KEEP:-0}" != 1 ]]; then compose --profile exits --profile clients down -v --remove-orphans >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
compose --profile exits --profile clients down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf "$OUT" && mkdir -p "$OUT/bin" "$OUT/tls" "$OUT/sing-box" "$CACHE"

echo "== build (linux/$ARCH)"
(cd "$ROOT/controlplane" && CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -o "$OUT/bin/cc-controlplane" .)
(cd "$ROOT/egress/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath \
  -ldflags "-X main.version=agent-usage-e2e" -o "$OUT/bin/agent-new" .)
old="$(mktemp -d)"
git -C "$ROOT" archive "$OLD_AGENT_REF" egress/agent | tar -x -C "$old"
(cd "$old/egress/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath \
  -ldflags "-X main.version=agent-${OLD_AGENT_REF:0:12}" -o "$OUT/bin/agent-old" .)
rm -rf "$old"

echo "== sing-box: pinned linux-$ARCH package"
read -r asset sum url < <(python3 - "$ROOT/controlplane/install/sing-box.json" "linux-$ARCH" <<'PY'
import json, sys
pin = json.load(open(sys.argv[1]))
a = pin["assets"][sys.argv[2]]
print(a["file"], a["sha256"], pin["url"].format(version=pin["version"], asset=a["file"]))
PY
)
src="${SINGBOX_ASSET_DIR:-$CACHE}/$asset"
if [[ ! -f "$src" ]]; then src="$CACHE/$asset"; curl -fsSL -o "$src" "$url"; fi
got="$( (command -v sha256sum >/dev/null && sha256sum "$src" || shasum -a 256 "$src") | cut -d' ' -f1)"
if [[ "$got" != "$sum" ]]; then echo "SHA-256 mismatch for $asset: $got" >&2; exit 1; fi
tar -xzf "$src" -C "$OUT/sing-box" --strip-components=1
echo "$asset sha256 $got"

echo "== TLS for the control plane"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=usage-e2e CA" \
  -addext "basicConstraints=critical,CA:TRUE" -keyout "$OUT/tls/ca-key.pem" -out "$OUT/tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=cp" \
  -keyout "$OUT/tls/cp-key.pem" -out "$OUT/tls/cp.csr" 2>/dev/null
printf 'subjectAltName=IP:10.88.1.5,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > "$OUT/tls/ext.cnf"
openssl x509 -req -in "$OUT/tls/cp.csr" -CA "$OUT/tls/ca.pem" -CAkey "$OUT/tls/ca-key.pem" -CAcreateserial \
  -days 2 -extfile "$OUT/tls/ext.cnf" -out "$OUT/tls/cp.pem" 2>/dev/null
chmod 644 "$OUT/tls/"*.pem

echo "== start control plane"
compose up -d --wait db cp sink decoy 2>&1 | tail -n 1
python3 "$HERE/driver.py"
