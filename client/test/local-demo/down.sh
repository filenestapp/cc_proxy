#!/usr/bin/env bash
# Stop the local demo started by up.sh. Disconnect in the app first.
HERE="$(cd "$(dirname "$0")" && pwd)"
docker compose -f "$HERE/compose.yaml" down -v --remove-orphans >/dev/null 2>&1
rm -rf "$HERE/out"
echo "demo stopped"
