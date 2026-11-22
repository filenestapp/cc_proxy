#!/usr/bin/env bash
# Put the two sidecars the desktop bundle ships into src-tauri/binaries/, named the way Tauri expects
# (<name>-<rust target triple>[.exe]):
#   ccproxy   built from client/cli for TARGET
#   sing-box  official release for TARGET, verified against the SHA-256 digest GitHub publishes for the asset
#
#   scripts/fetch-binaries.sh [TARGET]      TARGET defaults to the host triple, e.g. aarch64-apple-darwin
set -euo pipefail

SINGBOX_VERSION="1.14.4"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../.." && pwd)"
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
chmod +x "$BIN/"*
ls -l "$BIN"
