#!/bin/sh
# Start a TUN client the way the OS would see it: default route via $GATEWAY, system resolver $RESOLVER,
# routing table recorded before sing-box starts, then wait for the TUN interface.
set -eu
ip route replace default via "$GATEWAY"
ip route show > /tmp/route.before
echo "nameserver $RESOLVER" > /etc/resolv.conf
sing-box run -c /etc/client/config.json -D /tmp &
pid=$!
for _ in $(seq 1 50); do
  ip -o link | grep -qE '^[0-9]+: tun[0-9]+:' && break
  sleep 0.2
done
ip -o link | grep -E '^[0-9]+: tun[0-9]+:'
touch /tmp/ready
wait $pid
