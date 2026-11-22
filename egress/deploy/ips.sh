#!/bin/sh
# Put the egress IPs on (or take them off) a network interface, and check what each one looks like from outside.
#
#   ips.sh up     IFACE IPS_FILE        add every IP as /32 (idempotent)
#   ips.sh down   IFACE IPS_FILE        remove them
#   ips.sh verify IFACE IPS_FILE [URL]  request URL bound to each IP; the reply must be that IP
#
# IPS_FILE has one IPv4 address per line (output of `gen.py ips`). The provider must route these
# addresses to this host; adding them to the interface alone is not enough.
# POSIX sh so it also runs under busybox.
set -eu

usage() { echo "usage: $0 up|down|verify IFACE IPS_FILE [URL]" >&2; exit 2; }
[ $# -ge 3 ] || usage
cmd=$1 iface=$2 file=$3
url=${4:-https://api.ipify.org}

ips() { grep -Ev '^[[:space:]]*(#|$)' "$file"; }

case $cmd in
  up)
    for ip in $(ips); do
      ip addr replace "$ip/32" dev "$iface"
    done
    echo "up: $(ips | wc -l | tr -d ' ') address(es) on $iface"
    ;;
  down)
    for ip in $(ips); do
      ip addr del "$ip/32" dev "$iface" 2>/dev/null || true
    done
    echo "down: removed from $iface"
    ;;
  verify)
    bad=0
    for ip in $(ips); do
      seen=$(curl -4 -fsS --max-time 10 --interface "$ip" "$url" 2>/dev/null || echo "ERR")
      if [ "$seen" = "$ip" ]; then
        echo "ok   $ip"
      else
        echo "FAIL $ip -> $seen"
        bad=$((bad + 1))
      fi
    done
    [ "$bad" -eq 0 ]
    ;;
  *) usage ;;
esac
