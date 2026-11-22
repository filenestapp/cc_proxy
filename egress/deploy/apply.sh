#!/bin/sh
# Apply an inventory on the exit node: render, validate, install, add IPs, reload sing-box.
#
#   sudo /opt/egress/deploy/apply.sh /etc/egress/inventory.json
#
# Expects: sing-box installed from the official package (unit sing-box.service, config
# /etc/sing-box/config.json, ExecReload sends SIGHUP), python3, and /etc/egress/env with EGRESS_IFACE.
# A failed check leaves the running config untouched. Reload drops connections that are open at that moment.
set -eu

inv=${1:-/etc/egress/inventory.json}
root=$(cd "$(dirname "$0")/.." && pwd)
conf=/etc/sing-box/config.json
. /etc/egress/env

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

python3 "$root/gen.py" server "$inv" -o "$tmp/config.json"
python3 "$root/gen.py" ips "$inv" > "$tmp/ips.txt"
sing-box check -c "$tmp/config.json"

install -m 0644 "$tmp/ips.txt" /etc/egress/ips.txt
"$root/deploy/ips.sh" up "$EGRESS_IFACE" /etc/egress/ips.txt

[ -f "$conf" ] && cp "$conf" "$conf.prev"
install -m 0600 "$tmp/config.json" "$conf"

if systemctl is-active --quiet sing-box; then
  systemctl reload sing-box
else
  systemctl enable --now sing-box
fi
echo "applied $inv (previous config kept at $conf.prev)"
