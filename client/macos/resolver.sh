#!/bin/bash
# Per-domain DNS on macOS for domain mode: only the listed domains (and their subdomains) are resolved by the
# sing-box TUN; every other name keeps using the system resolvers. System DNS settings are not touched.
#
#   sudo resolver.sh install DOMAIN...   write /etc/resolver/<domain> -> TUN DNS address
#   sudo resolver.sh remove              delete only the files this script wrote
#   resolver.sh status                   list managed files and what macOS reports for them
#
# RESOLVER_DIR overrides /etc/resolver (for testing without root).
set -euo pipefail

DIR="${RESOLVER_DIR:-/etc/resolver}"
NAMESERVER="${TUN_DNS:-172.19.0.2}"
MARK="# managed by cc_proxy"

managed() {
  [[ -d "$DIR" ]] || return 0
  grep -l -F -x "$MARK" "$DIR"/* 2>/dev/null || true
}

case "${1:-}" in
  install)
    shift
    [[ $# -gt 0 ]] || { echo "usage: $0 install DOMAIN..." >&2; exit 2; }
    mkdir -p "$DIR"
    for d in "$@"; do
      [[ "$d" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad domain: $d" >&2; exit 2; }
      f="$DIR/$d"
      if [[ -e "$f" ]] && ! grep -q -F -x "$MARK" "$f"; then
        echo "skip $f: exists and is not managed by this script" >&2
        continue
      fi
      printf '%s\nnameserver %s\n' "$MARK" "$NAMESERVER" > "$f"
      echo "installed $f -> $NAMESERVER"
    done
    ;;
  remove)
    for f in $(managed); do rm -f "$f" && echo "removed $f"; done
    ;;
  status)
    files=$(managed)
    [[ -n "$files" ]] || { echo "no managed resolver files in $DIR"; exit 0; }
    for f in $files; do echo "$f: $(grep nameserver "$f")"; done
    if [[ "$DIR" == /etc/resolver ]] && command -v scutil >/dev/null; then
      scutil --dns | grep -B1 -A3 -E "domain +: ($(basename -a $files | paste -sd'|' -))$" || true
    fi
    ;;
  *)
    echo "usage: $0 install DOMAIN... | remove | status" >&2
    exit 2
    ;;
esac
