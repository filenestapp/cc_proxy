#!/bin/bash
# Run the prototype client on macOS in the foreground. Ctrl-C stops it and undoes the resolver entries.
#
#   sudo client/macos/run.sh CONFIG.json [INVENTORY.json]
#
# CONFIG is from `gen.py client INVENTORY DEVICE --mode domain|app`. For domain mode the domains are read
# from INVENTORY (client_policy.domain_suffix) and installed under /etc/resolver while sing-box runs.
# Needs root (TUN) and sing-box on PATH (e.g. `brew install sing-box`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
gen="$here/../../egress/gen.py"
config="${1:?usage: $0 CONFIG.json [INVENTORY.json]}"
inventory="${2:-}"
state="/var/tmp/cc_proxy"

[[ $EUID -eq 0 ]] || { echo "run with sudo: the TUN interface needs root" >&2; exit 1; }
command -v sing-box >/dev/null || { echo "sing-box not found on PATH" >&2; exit 1; }
sing-box check -c "$config"

mode=$(python3 -c '
import json, sys
tun = [i for i in json.load(open(sys.argv[1])).get("inbounds", []) if i.get("type") == "tun"]
print("proxy" if not tun else "domain" if tun[0].get("route_address") else "app")' "$config")
echo "mode: $mode"

cleanup() { [[ "$mode" == domain ]] && "$here/resolver.sh" remove || true; }
trap cleanup EXIT INT TERM

if [[ "$mode" == domain ]]; then
  [[ -n "$inventory" ]] || { echo "domain mode needs INVENTORY to know which domains to send to the TUN" >&2; exit 2; }
  # shellcheck disable=SC2046
  "$here/resolver.sh" install $(python3 "$gen" domains "$inventory")
  dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true
fi

mkdir -p "$state"
sing-box run -c "$config" -D "$state"
