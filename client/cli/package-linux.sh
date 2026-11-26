#!/usr/bin/env bash
# Build a versioned, standalone Linux archive with the same pinned runtime as the desktop app.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
version="${1:?Usage: package-linux.sh VERSION MUSL_TARGET OUTPUT_DIRECTORY}"
target="${2:?Linux musl target required}"
out="${3:?Output directory required}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release version: $version" >&2
  exit 2
fi
case "$target" in
  x86_64-unknown-linux-musl) arch=x86_64 ;;
  aarch64-unknown-linux-musl) arch=arm64 ;;
  *) echo "Unsupported Linux target: $target" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
package="aifree-cli-$version-linux-$arch"
mkdir -p "$out" "$work/$package"
AIFREE_RELEASE_VERSION="$version" AIFREE_SIDECAR_DIR="$work/sidecars" \
  "$here/../desktop/scripts/fetch-binaries.sh" "$target"
for executable in aifree sing-box frpc; do
  install -m 755 "$work/sidecars/$executable-$target" "$work/$package/$executable"
done
archive="$package.tar.gz"
python3 - "$work/$package" "$out/$archive" <<'PYTHON'
from pathlib import Path
import sys
import tarfile


def root_owned(entry):
    entry.uid = entry.gid = 0
    entry.uname = entry.gname = "root"
    return entry


source = Path(sys.argv[1])
with tarfile.open(sys.argv[2], "w:gz", compresslevel=6) as archive:
    archive.add(source, arcname=source.name, filter=root_owned)
PYTHON
(cd "$out" && sha256sum "$archive" > "$archive.sha256")
