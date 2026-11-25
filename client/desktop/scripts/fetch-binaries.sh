#!/usr/bin/env bash
# Put the three sidecars the desktop bundle ships into src-tauri/binaries/, named the way Tauri expects
# (<name>-<rust target triple>[.exe]):
#   ccproxy   built from client/cli for TARGET
#   sing-box  official release for TARGET, verified against the SHA-256 digest GitHub publishes for the asset
#   frpc      official frp release for TARGET (the XTCP visitor), verified against the SHA-256 pin the exit
#             installer uses (controlplane/install/frpc.json); the build stops if the pin is missing or differs
#
#   scripts/fetch-binaries.sh [TARGET]      TARGET defaults to the host triple, e.g. aarch64-apple-darwin
set -euo pipefail

SINGBOX_VERSION="1.14.4"
FRP_VERSION="0.72.0"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../.." && pwd)"
FRP_PINS="$CLIENT/../controlplane/install/frpc.json"
BIN="$HERE/../src-tauri/binaries"
TARGET="${1:-$(rustc -vV | awk '/^host:/ {print $2}')}"

case "$TARGET" in
  aarch64-apple-darwin)        asset="darwin-arm64";   ext="tar.gz"; exe="" ;;
  x86_64-apple-darwin)         asset="darwin-amd64";   ext="tar.gz"; exe="" ;;
  x86_64-unknown-linux-gnu)    asset="linux-amd64";    ext="tar.gz"; exe="" ;;
  aarch64-unknown-linux-gnu)   asset="linux-arm64";    ext="tar.gz"; exe="" ;;
  x86_64-pc-windows-msvc)      asset="windows-amd64";  ext="zip";    exe=".exe" ;;
  aarch64-pc-windows-msvc)     asset="windows-arm64";  ext="zip";    exe=".exe" ;;
  *) echo "unsupported target $TARGET" >&2; exit 2 ;;
esac
mkdir -p "$BIN"

echo "== ccproxy for $TARGET"
(cd "$CLIENT" && cargo build --release -p ccproxy --target "$TARGET")
cp "$CLIENT/target/$TARGET/release/ccproxy$exe" "$BIN/ccproxy-$TARGET$exe"

name="sing-box-$SINGBOX_VERSION-$asset"
url="https://github.com/SagerNet/sing-box/releases/download/v$SINGBOX_VERSION/$name.$ext"
echo "== sing-box $SINGBOX_VERSION ($asset)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/$name.$ext" "$url"
PY="$(command -v python3 || command -v python)"   # Windows runners ship "python" only
want=$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v$SINGBOX_VERSION" |
  "$PY" -c "import json,sys; a=[x for x in json.load(sys.stdin)['assets'] if x['name']==sys.argv[1]]; print((a[0].get('digest') or '').removeprefix('sha256:') if a else '')" "$name.$ext")
if command -v sha256sum >/dev/null; then hash=(sha256sum); else hash=(shasum -a 256); fi
got=$("${hash[@]}" "$work/$name.$ext" | awk '{print $1}')
if [[ -z "$want" ]]; then
  echo "GitHub publishes no digest for $name.$ext; refusing to bundle an unverified binary" >&2; exit 1
fi
[[ "$want" == "$got" ]] || { echo "sha256 mismatch for $name.$ext: want $want got $got" >&2; exit 1; }
echo "sha256 ok ($got)"
if [[ "$ext" == "zip" ]]; then (cd "$work" && unzip -q "$name.$ext"); else tar -xzf "$work/$name.$ext" -C "$work"; fi
cp "$work/$name/sing-box$exe" "$BIN/sing-box-$TARGET$exe"

echo "== frpc $FRP_VERSION ($asset)"
# The pin file names the asset and its digest; refuse a version or asset it does not pin.
read -r frp_file frp_want < <("$PY" -c '
import json, sys
pins = json.load(open(sys.argv[1]))
if pins["version"] != sys.argv[2]:
    sys.exit("frpc.json pins %s, this script bundles %s" % (pins["version"], sys.argv[2]))
a = pins["assets"].get(sys.argv[3]) or sys.exit("frpc.json pins no asset for " + sys.argv[3])
print(a["file"], a["sha256"])' "$FRP_PINS" "$FRP_VERSION" "$asset")
[[ -n "$frp_file" && ${#frp_want} -eq 64 ]] || { echo "no usable frpc pin for $asset" >&2; exit 1; }
curl -fsSL -o "$work/$frp_file" "https://github.com/fatedier/frp/releases/download/v$FRP_VERSION/$frp_file"
got=$("${hash[@]}" "$work/$frp_file" | awk '{print $1}')
[[ "$frp_want" == "$got" ]] || { echo "sha256 mismatch for $frp_file: want $frp_want got $got" >&2; exit 1; }
echo "sha256 ok ($got)"
frp_dir="${frp_file%.tar.gz}"; frp_dir="${frp_dir%.zip}"
if [[ "$frp_file" == *.zip ]]; then (cd "$work" && unzip -q "$frp_file"); else tar -xzf "$work/$frp_file" -C "$work"; fi
cp "$work/$frp_dir/frpc$exe" "$BIN/frpc-$TARGET$exe"
chmod +x "$BIN/"*
ls -l "$BIN"
