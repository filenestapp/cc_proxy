#!/usr/bin/env bash
# Build the CLI sidecar and bundle the pinned sing-box and frpc releases with the desktop app.
# scripts/fetch-binaries.sh [TARGET] defaults to the host Rust target triple.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../.." && pwd)"
INSTALL_PINS="$CLIENT/../controlplane/install"
BIN="$HERE/../src-tauri/binaries"
TARGET="${1:-$(rustc -vV | awk '/^host:/ {print $2}')}"

case "$TARGET" in
  universal-apple-darwin)
    "$HERE/fetch-binaries.sh" aarch64-apple-darwin
    "$HERE/fetch-binaries.sh" x86_64-apple-darwin
    for executable in ccproxy sing-box frpc; do
      lipo -create -output "$BIN/$executable-$TARGET" \
        "$BIN/$executable-aarch64-apple-darwin" "$BIN/$executable-x86_64-apple-darwin"
      for arch in arm64 x86_64; do lipo -verify_arch "$arch" "$BIN/$executable-$TARGET"; done
    done
    exit 0 ;;
  aarch64-apple-darwin)        asset="darwin-arm64";   exe="" ;;
  x86_64-apple-darwin)         asset="darwin-amd64";   exe="" ;;
  x86_64-unknown-linux-gnu)    asset="linux-amd64";    exe="" ;;
  aarch64-unknown-linux-gnu)   asset="linux-arm64";    exe="" ;;
  x86_64-pc-windows-msvc)      asset="windows-amd64";  exe=".exe" ;;
  aarch64-pc-windows-msvc)     asset="windows-arm64";  exe=".exe" ;;
  *) echo "unsupported target $TARGET" >&2; exit 2 ;;
esac
mkdir -p "$BIN"

echo "== ccproxy for $TARGET"
(cd "$CLIENT" && cargo build --locked --release -p ccproxy --target "$TARGET")
cp "$CLIENT/target/$TARGET/release/ccproxy$exe" "$BIN/ccproxy-$TARGET$exe"

PY="$(command -v python3 || command -v python)"
if command -v sha256sum >/dev/null; then hash=(sha256sum); else hash=(shasum -a 256); fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch_pinned_sidecar() {
  local executable="$1" pin_file="$2"
  local filename digest url actual package_directory
  echo "== $executable ($asset)"
  read -r filename digest url < <("$PY" - "$pin_file" "$asset" <<'PYTHON_PIN'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    pins = json.load(source)
asset = pins["assets"].get(sys.argv[2])
if not asset or not re.fullmatch(r"[0-9a-f]{64}", asset.get("sha256", "")):
    sys.exit(f"No SHA-256 pin for {sys.argv[2]} in {sys.argv[1]}")
filename = asset["file"]
url = pins["url"].format(version=pins["version"], asset=filename)
# Write LF explicitly so bash receives the same fields on Windows.
sys.stdout.buffer.write(f"{filename} {asset['sha256']} {url}\n".encode("ascii"))
PYTHON_PIN
)
  curl -fsSL --retry 3 --max-time 300 -o "$work/$filename" "$url"
  actual=$("${hash[@]}" "$work/$filename" | awk '{print $1}')
  if [[ "$actual" != "$digest" ]]; then
    echo "sha256 mismatch for $filename: want $digest got $actual" >&2
    exit 1
  fi
  echo "sha256 ok ($actual)"
  case "$filename" in
    *.zip)
      (cd "$work" && unzip -q "$filename")
      package_directory="${filename%.zip}" ;;
    *.tar.gz)
      tar -xzf "$work/$filename" -C "$work"
      package_directory="${filename%.tar.gz}" ;;
    *)
      echo "unsupported archive $filename" >&2
      exit 1 ;;
  esac
  cp "$work/$package_directory/$executable$exe" "$BIN/$executable-$TARGET$exe"
}

fetch_pinned_sidecar sing-box "$INSTALL_PINS/sing-box.json"
fetch_pinned_sidecar frpc "$INSTALL_PINS/frpc.json"
chmod +x "$BIN/"*
ls -l "$BIN"
