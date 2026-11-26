#!/bin/sh
# Reproducible build of ccproxy-exit-agent for every supported exit-node platform.
#
#   egress/agent/build.sh [--verify] [VERSION]
#
# Release builds (AGENT_RELEASE_BUILD=1) use the semantic version in RELEASE_VERSION and require its source tag.
# Normal local builds add a development suffix. VERSION overrides the local label for test fixtures and older callers.
#
# Output: egress/agent/dist/ccproxy-exit-agent-<os>-<arch>[.exe] and dist/SHA256SUMS. The control plane serves
# these files to the installers (GET /install/agent/<os>-<arch>) and embeds their SHA-256 in the install scripts,
# so a node verifies the binary it downloads. Same source + same VERSION gives byte-identical binaries: pinned Go
# toolchain (go.mod), no cgo, -trimpath, no VCS stamping, empty build ID. Check with: build.sh twice and compare
# SHA256SUMS, or `build.sh --verify` which does exactly that.
#
# The agent trusts the release signing keys in release_keys.txt (automatic updates, docs/exit-agent-updates.md).
# AGENT_EXTRA_RELEASE_KEYS ("ed25519:..." keys, comma separated) adds more for test builds only, such as the e2e
# rehearsal in controlplane/test/xtcp; never set it for a build that goes to real hosts.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
verify=
if [ "${1:-}" = --verify ]; then verify=1; shift; fi
fail() { printf '%s\n' "$1" >&2; exit 2; }
[ "$#" -le 1 ] || fail "usage: $0 [--verify] [VERSION]"
if [ "${AGENT_RELEASE_BUILD:-}" = 1 ] && [ "$#" -ne 0 ]; then
  fail "a release build takes its version from RELEASE_VERSION"
fi
version=${1:-}
if [ -z "$version" ]; then
  release_version=$(cat RELEASE_VERSION)
  case $release_version in
    *[!v.0-9]*) fail "RELEASE_VERSION must be vMAJOR.MINOR.PATCH" ;;
  esac
  printf '%s\n' "$release_version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
    fail "RELEASE_VERSION must be vMAJOR.MINOR.PATCH"
  if [ "${AGENT_RELEASE_BUILD:-}" = 1 ]; then
    [ -z "${AGENT_EXTRA_RELEASE_KEYS:-}" ] || fail "a release build cannot include fixture signing keys"
    [ -z "$(git status --porcelain -- .)" ] || fail "a release build requires a clean Agent source checkout"
    head=$(git rev-parse HEAD)
    source_tag=exit-agent/$release_version
    [ "$(git rev-parse --quiet --verify "refs/tags/$source_tag^{commit}")" = "$head" ] ||
      fail "a release build requires Git tag $source_tag at HEAD"
    version=$release_version
  else
    tree=$(git rev-parse --short=12 HEAD:egress/agent 2>/dev/null || echo unknown)
    version=$release_version-dev.$tree
    if [ -n "$(git status --porcelain -- . 2>/dev/null)" ]; then version=$version-dirty; fi
  fi
fi
case $version in
  *[!A-Za-z0-9._+-]*) fail "agent version contains unsupported characters" ;;
esac
[ "${#version}" -le 64 ] || fail "agent version must not exceed 64 characters"
toolchain=$(sed -n 's/^toolchain //p' go.mod)
targets="darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64"

build() { # build OUTDIR
  out=$1
  rm -rf "$out"
  mkdir -p "$out"
  for t in $targets; do
    os=${t%/*} arch=${t#*/} ext=
    [ "$os" = windows ] && ext=.exe
    GOTOOLCHAIN=$toolchain CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOFLAGS=-mod=readonly \
      go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=$version${AGENT_EXTRA_RELEASE_KEYS:+ -X main.extraReleaseKeys=$AGENT_EXTRA_RELEASE_KEYS}" \
      -o "$out/ccproxy-exit-agent-$os-$arch$ext" .
  done
  (cd "$out" && if command -v sha256sum >/dev/null 2>&1; then sha256sum ccproxy-exit-agent-*; else shasum -a 256 ccproxy-exit-agent-*; fi) > "$out/SHA256SUMS.tmp"
  mv "$out/SHA256SUMS.tmp" "$out/SHA256SUMS"
  printf '%s\n' "$version" > "$out/VERSION"
}

build dist
if [ -n "$verify" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  build "$tmp/again"
  if cmp -s dist/SHA256SUMS "$tmp/again/SHA256SUMS"; then
    echo "reproducible: a second build gave identical binaries"
  else
    diff dist/SHA256SUMS "$tmp/again/SHA256SUMS" >&2
    echo "NOT reproducible" >&2
    exit 1
  fi
fi
if [ -n "${AGENT_EXTRA_RELEASE_KEYS:-}" ]; then echo "WARNING: test build, extra release keys: $AGENT_EXTRA_RELEASE_KEYS" >&2; fi
echo "ccproxy-exit-agent $version ($toolchain):"
cat dist/SHA256SUMS
