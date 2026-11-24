#!/bin/sh
# CC Proxy exit-node installer for macOS and Linux. The control plane serves this file at /install/exit.sh with
# the digests below filled in; copy the command from the console (Egress hosts -> host -> Install command). It
# downloads over HTTPS only (no redirect may downgrade it) into a file first, so a failed download never reaches sudo:
#
#   (f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
#     'https://cp.example/install/exit.sh' -o "$f" && sudo sh "$f" --cp 'https://cp.example' [--iface eth0];
#     s=$?; rm -f "$f"; exit $s)
#   The subshell removes the temporary file and exits with the status of curl or this script.
#   (the same with --uninstall instead of --cp ...)
#
# Nothing has to be installed first: the node needs only curl and, on Linux, systemd. The installer downloads the
# compiled exit agent from the control plane (with the host's token) and the pinned official sing-box release from
# GitHub, and checks both against the SHA-256 digests below before anything runs.
#
# The host's agent token is read from the terminal without echo (or from --token-file). It never appears in a
# command line, shell history, process list, service definition or log: curl reads it from stdin, the agent from
# /etc/ccproxy-exit/agent.token (root, 0600). Requests that carry the token never follow redirects. Running the
# installer again is safe: it upgrades the files, keeps the last configuration and, when you press Enter at the
# prompt, the existing token. Enter a new token there after rotating it in the console.
#
# Installed (all root-owned and writable by root only; checked, with every directory above, before start):
#   /opt/ccproxy-exit/bin/{ccproxy-exit-agent,sing-box}   agent and pinned sing-box
#   /opt/ccproxy-exit/libexec/singbox-ctl                 reload / status helper the agent calls
#   /etc/ccproxy-exit/{agent.token,install.conf}          token (0600) and the options of this installation
#   /var/lib/ccproxy-exit/                                config.json sing-box runs, agent and sing-box state (0700)
#   Linux: systemd units ccproxy-exit-singbox, ccproxy-exit-agent and, with --iface, ccproxy-exit-ips
#   macOS: launchd daemons com.ccproxy.exit.singbox and com.ccproxy.exit.agent; logs in /var/log/ccproxy-exit
#   XTCP hosts (set in the console): /opt/ccproxy-exit/bin/frpc (pinned official frp release, SHA-256 checked),
#   /etc/ccproxy-exit/frpc.toml (0600: frps token and XTCP secret key) and frp-ca.pem, run by systemd unit
#   ccproxy-exit-frpc or launchd daemon com.ccproxy.exit.frpc. frpc registers an xtcp proxy for sing-box with frps
#   (TLS on TCP 7003, verified against that CA); visitors connect directly, with no relay fallback.
# Both start at boot without anyone logging in. sing-box starts from the last confirmed config even when the
# control plane is unreachable; the agent keeps it in step once it can reach the control plane.
#
# Options:
#   --cp URL           control plane base URL (https). Remembered for reruns.
#   --iface IFACE      Linux only: add the host's routed egress IPs to IFACE. Remembered; --no-iface drops it.
#   --token-file FILE  read the agent token from FILE instead of prompting (for automation)
#   --cafile FILE      CA bundle when the control plane uses a private certificate. Remembered.
#   --name NAME        agent name in its logs (default: the hostname). Remembered.
#   --uninstall        stop and remove everything this installer created (including the token)
set -eu

# @@INSTALLER_DATA@@

PROG=ccproxy-exit
ROOT=${CCPROXY_EXIT_TEST_ROOT:-}         # tests only: install under this directory and skip the root check
PREFIX=$ROOT/opt/ccproxy-exit
ETC=$ROOT/etc/ccproxy-exit
VAR=$ROOT/var/lib/ccproxy-exit
LOGDIR=$ROOT/var/log/ccproxy-exit
SYSTEMD_DIR=$ROOT/etc/systemd/system
LAUNCHD_DIR=$ROOT/Library/LaunchDaemons
NEWSYSLOG_DIR=$ROOT/etc/newsyslog.d
AGENT=$PREFIX/bin/ccproxy-exit-agent
SINGBOX=$PREFIX/bin/sing-box
CTL=$PREFIX/libexec/singbox-ctl
TOKEN_FILE=$ETC/agent.token
CONF_FILE=$ETC/install.conf
MAC_SINGBOX=com.ccproxy.exit.singbox
MAC_AGENT=com.ccproxy.exit.agent
MAC_FRPC=com.ccproxy.exit.frpc
FRPC=$PREFIX/bin/frpc
FRPC_CONF=$ETC/frpc.toml
FRP_CA=$ETC/frp-ca.pem
NL='
'

say() { printf '%s\n' "$PROG: $*" >&2; }
die() { say "error: $*"; exit 1; }

# valid REGEX VALUE: VALUE is a single line that matches the extended regex. The patterns stay within what BSD
# grep accepts (repetition counts up to 255).
valid() {
  case $2 in *"$NL"*) return 1 ;; esac
  printf '%s\n' "$2" | grep -Eq "$1"
}
RE_URL='^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'
RE_IFACE='^[A-Za-z0-9_.:-]{1,15}$'
RE_NAME='^[A-Za-z0-9_.-]{1,64}$'
RE_PATH='^/[A-Za-z0-9 _./+@-]*$'
RE_TOKEN='^[A-Za-z0-9_-]+$'      # length is checked separately: BSD grep caps ERE repetition counts at 255

conf_get() { [ -f "$CONF_FILE" ] && sed -n "s/^$1='\\(.*\\)'\$/\\1/p" "$CONF_FILE" | head -n 1 || true; }

usage() {
  cat >&2 <<'EOF'
usage: sudo sh exit.sh --cp https://<cp> [--iface IFACE | --no-iface] [--token-file FILE] [--cafile FILE] [--name NAME]
       sudo sh exit.sh --uninstall
Copy the complete command (download, then run) from the console: Egress hosts -> host -> Install command.
EOF
  exit 2
}

work=
tty_saved=
cleanup() {
  if [ -n "$tty_saved" ]; then stty "$tty_saved" < /dev/tty 2>/dev/null || true; fi
  if [ -n "$work" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

main() {
  cp_url='' iface='' token_src='' cafile='' name='' uninstall='' no_iface=''
  while [ $# -gt 0 ]; do
    case $1 in
      --cp) [ $# -ge 2 ] || usage; cp_url=$2; shift 2 ;;
      --iface) [ $# -ge 2 ] || usage; iface=$2; shift 2 ;;
      --no-iface) no_iface=1; shift ;;
      --token-file) [ $# -ge 2 ] || usage; token_src=$2; shift 2 ;;
      --cafile) [ $# -ge 2 ] || usage; cafile=$2; shift 2 ;;
      --name) [ $# -ge 2 ] || usage; name=$2; shift 2 ;;
      --uninstall) uninstall=1; shift ;;
      -h|--help) usage ;;
      *) say "unknown option $1"; usage ;;
    esac
  done

  if [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then
    die "run as root: copy the install command from the console (it runs this script with sudo)"
  fi
  os=${CCPROXY_EXIT_TEST_OS:-$(uname -s)}
  case $os in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) die "unsupported system $os (macOS and Linux only; use the Windows command on Windows)" ;;
  esac

  if [ -n "$uninstall" ]; then
    do_uninstall
    return
  fi

  # Options not given on a rerun keep the values of the existing installation.
  [ -n "$cp_url" ] || cp_url=$(conf_get CP_URL)
  [ -n "$iface" ] || [ -n "$no_iface" ] || iface=$(conf_get IFACE)
  [ -n "$cafile" ] || cafile=$(conf_get CAFILE)
  [ -n "$name" ] || name=$(conf_get AGENT_NAME)

  [ -n "$cp_url" ] || die "pass --cp https://<control plane>"
  cp_url=${cp_url%/}
  valid "$RE_URL" "$cp_url" ||
    die "--cp must be the https URL of the control plane, such as https://cp.example:8443 (plain http is refused)"
  if [ -n "$iface" ]; then
    [ "$os" = linux ] || die "--iface is Linux-only. On macOS the Mac's existing local IPv4 is the egress IP; add that address to the host in the console."
    valid "$RE_IFACE" "$iface" || die "--iface: invalid interface name"
  fi
  [ -z "$name" ] || valid "$RE_NAME" "$name" || die "--name: use letters, digits, '.', '_' or '-'"
  if [ -n "$cafile" ]; then
    valid "$RE_PATH" "$cafile" && [ -f "$cafile" ] || die "--cafile must be an existing absolute path"
    trusted "$cafile" || die "--cafile $cafile is changeable by a non-root user; a root service must not trust it"
  fi
  command -v curl >/dev/null 2>&1 || die "curl is required"

  case ${CCPROXY_EXIT_TEST_ARCH:-$(uname -m)} in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=amd64 ;;
    *) die "unsupported CPU $(uname -m)" ;;
  esac
  platform=$os-$arch
  agent_sha=$(agent_sha256 "$platform")
  asset_file=$(singbox_asset_file "$platform")
  asset_sha=$(singbox_asset_sha256 "$platform")
  [ -n "$agent_sha" ] && [ -n "$asset_file" ] && [ -n "$asset_sha" ] || die "no build for $platform"

  # In sticky /tmp, not the caller's $TMPDIR: an unprivileged owner of the parent could swap a root-owned work dir.
  mkdir -p "$ROOT/tmp"
  work=$(mktemp -d "$ROOT/tmp/ccproxy-exit.XXXXXX")

  read_token
  say "checking the control plane and the token"
  code=$(cp_curl -o /dev/null -w '%{http_code}' "$cp_url/agent/probe-targets") ||
    die "cannot reach $cp_url (private certificate? pass --cafile); nothing was changed"
  case $code in
    200) ;;
    401) die "the control plane rejected the token (rotated, or for another control plane?); nothing was changed" ;;
    *) die "the control plane answered HTTP $code; nothing was changed" ;;
  esac

  say "downloading ccproxy-exit-agent $AGENT_VERSION ($platform)"
  cp_curl -f -o "$work/ccproxy-exit-agent" "$cp_url/install/agent/$platform" ||
    die "agent download failed; nothing was changed"
  check_sha "$work/ccproxy-exit-agent" "$agent_sha" || die "agent SHA-256 mismatch; nothing was changed"

  singbox_new=
  if [ -x "$SINGBOX" ] && [ "$(cat "$PREFIX/sing-box.sha256" 2>/dev/null || true)" = "$asset_sha" ]; then
    say "sing-box $SINGBOX_VERSION already installed"
  else
    say "downloading sing-box $SINGBOX_VERSION ($platform)"
    base=${CCPROXY_EXIT_SINGBOX_BASE_URL:-$SINGBOX_BASE_URL}   # a mirror must still match the pinned digest
    valid '^https://' "$base" || die "sing-box must be downloaded over https"
    # GitHub redirects release downloads to its CDN: follow, but https only. No token is sent here.
    curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$work/$asset_file" "$base/$asset_file" </dev/null ||
      die "sing-box download failed; nothing was changed"
    check_sha "$work/$asset_file" "$asset_sha" ||
      die "sing-box SHA-256 does not match the pinned digest; nothing was changed"
    mkdir -p "$work/sb"
    tar -xzf "$work/$asset_file" -C "$work/sb"
    dir=${asset_file%.tar.gz}
    [ -f "$work/sb/$dir/sing-box" ] || die "sing-box binary missing from $asset_file"
    singbox_new=$work/sb/$dir/sing-box
  fi

  # Transport: the control plane answers 200 with this host's frpc configuration when it uses XTCP, 204 when it uses
  # the public entry. The request carries the host token, like the agent download.
  xtcp='' frpc_new='' frpc_sha=''
  code=$(cp_curl -o "$work/frpc.toml" -w '%{http_code}' "$cp_url/install/xtcp/frpc.toml?ca_file=$(urlencode "$FRP_CA")") ||
    die "cannot read the host's transport settings; nothing was changed"
  case $code in
    204) say "transport: public entry (no frpc)" ;;
    200)
      xtcp=1
      cp_curl -f -o "$work/frp-ca.pem" "$cp_url/install/xtcp/ca.pem" && [ -s "$work/frp-ca.pem" ] ||
        die "cannot read the CA for frps; nothing was changed"
      frpc_file=$(frpc_asset_file "$platform")
      frpc_sha=$(frpc_asset_sha256 "$platform")
      [ -n "$frpc_file" ] && [ -n "$frpc_sha" ] || die "no pinned frpc build for $platform"
      if [ -x "$FRPC" ] && [ "$(cat "$PREFIX/frpc.sha256" 2>/dev/null || true)" = "$frpc_sha" ]; then
        say "frpc $FRPC_VERSION already installed"
      else
        say "downloading frpc $FRPC_VERSION ($platform)"
        base=${CCPROXY_EXIT_FRPC_BASE_URL:-$FRPC_BASE_URL}   # a mirror must still match the pinned digest
        valid '^https://' "$base" || die "frpc must be downloaded over https"
        curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$work/$frpc_file" "$base/$frpc_file" </dev/null ||
          die "frpc download failed; nothing was changed"
        check_sha "$work/$frpc_file" "$frpc_sha" ||
          die "frpc SHA-256 does not match the pinned digest; nothing was changed"
        mkdir -p "$work/frp"
        tar -xzf "$work/$frpc_file" -C "$work/frp"
        dir=${frpc_file%.tar.gz}
        [ -f "$work/frp/$dir/frpc" ] || die "frpc binary missing from $frpc_file"
        frpc_new=$work/frp/$dir/frpc
      fi
      say "transport: XTCP (frpc proxy for sing-box; direct connections only, no relay)"
      ;;
    *) die "the control plane answered HTTP $code for the transport settings; nothing was changed" ;;
  esac

  install_files
  write_token
  write_conf
  verify_installed
  if [ "$os" = linux ]; then install_linux; else install_macos; fi
  token=

  say "installed. The host shows a fresh heartbeat in the console within a minute."
  if [ "$os" = linux ]; then
    say "logs: journalctl -u ccproxy-exit-agent -u ccproxy-exit-singbox${xtcp:+ -u ccproxy-exit-frpc} -f"
  else
    say "logs: tail -f $LOGDIR/agent.log $LOGDIR/sing-box.log${xtcp:+ $LOGDIR/frpc.log}"
    mac_warnings
  fi
  say "uninstall: copy the uninstall command from the console, or run this script again with --uninstall"
}

# curl to the control plane with the token. -q comes first so no curlrc can add options (such as --location); the
# header comes from a curl config on stdin, so the token is in no argument list; without -L no redirect is followed,
# so it only goes to --cp.
cp_curl() {
  printf 'header = "Authorization: Bearer %s"\n' "$token" |
    curl -q --config - --proto '=https' --tlsv1.2 -sS --max-time 120 ${cafile:+--cacert "$cafile"} "$@"
}

urlencode() { printf '%s' "$1" | sed 's/%/%25/g; s/ /%20/g; s/+/%2B/g; s/@/%40/g'; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

check_sha() { [ "$(sha256_of "$1")" = "$2" ]; }

read_token() {
  token=
  if [ -n "$token_src" ]; then
    [ -r "$token_src" ] || die "cannot read --token-file $token_src"
    token=$(head -n 1 "$token_src" | tr -d '\r\n ')
  elif [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then
    hint="paste the host's agent token"
    [ -s "$TOKEN_FILE" ] && hint="$hint, or press Enter to keep the installed token"
    printf '%s (input hidden): ' "$hint" > /dev/tty
    tty_saved=$(stty -g < /dev/tty)
    stty -echo < /dev/tty
    IFS= read -r token < /dev/tty || true
    stty "$tty_saved" < /dev/tty
    tty_saved=
    printf '\n' > /dev/tty
    token=$(printf '%s' "$token" | tr -d '\r\n ')
  fi
  if [ -z "$token" ] && [ -s "$TOKEN_FILE" ]; then
    token=$(head -n 1 "$TOKEN_FILE" | tr -d '\r\n ')
    say "keeping the installed token"
  fi
  [ -n "$token" ] || die "no agent token: run in a terminal to be prompted, or pass --token-file"
  if ! valid "$RE_TOKEN" "$token" || [ "${#token}" -lt 16 ] || [ "${#token}" -gt 256 ]; then
    die "that does not look like an agent token (copy it from the console)"
  fi
}

# -- trusted paths ------------------------------------------------------------------------------------------
# A root daemon must not run anything a normal user can change: each path component, up to /, must be owned by root
# and not writable by group (unless group 0) or others, with no ACL. Symlinks are checked and then followed.

TEST_TRUSTED_UID=${CCPROXY_EXIT_TEST_TRUSTED_UID:-}   # tests only: also trust this uid, for paths under $ROOT

# shellcheck disable=SC2012  # ls -ldn is the portable owner/mode query on both macOS and Linux
entry_ok() {
  meta=$(ls -ldn "$1" 2>/dev/null) || return 1
  perms=$(printf '%s\n' "$meta" | awk '{print $1}')
  uid=$(printf '%s\n' "$meta" | awk '{print $3}')
  gid=$(printf '%s\n' "$meta" | awk '{print $4}')
  if [ "$uid" != 0 ]; then
    [ -n "$ROOT" ] && [ -n "$TEST_TRUSTED_UID" ] && [ "$uid" = "$TEST_TRUSTED_UID" ] || return 1
    case $1 in "$ROOT"|"$ROOT"/*) ;; *) return 1 ;; esac
  fi
  case $perms in l*) return 0 ;; esac          # a link's own mode means nothing; its owner and target count
  case $perms in ??????????+*) return 1 ;; esac  # an ACL may grant write access
  [ "$(printf '%s' "$perms" | cut -c9)" != w ] || return 1
  [ "$(printf '%s' "$perms" | cut -c6)" != w ] || [ "$gid" = 0 ] || return 1
}

# shellcheck disable=SC2012
chain_ok() { # PATH and every directory above it
  p=$1
  while :; do
    if ! entry_ok "$p"; then
      say "not trusted: $p ($(ls -ldn "$p" 2>/dev/null | awk '{print $1, "uid=" $3, "gid=" $4}'))"
      return 1
    fi
    [ "$p" != / ] || return 0
    if [ -n "$ROOT" ] && [ "$p" = "$ROOT" ]; then return 0; fi
    p=$(dirname "$p")
  done
}

resolve() { # physical path of $1
  p=$1 n=0
  while [ -L "$p" ]; do
    n=$((n + 1)); [ "$n" -le 40 ] || return 1
    t=$(readlink "$p")
    case $t in /*) p=$t ;; *) p=$(dirname "$p")/$t ;; esac
  done
  d=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd -P) || return 1
  printf '%s/%s\n' "${d%/}" "$(basename "$p")"
}

trusted() { # the path as given and as resolved
  chain_ok "$1" || return 1
  real=$(resolve "$1") || return 1
  [ "$real" = "$1" ] || chain_ok "$real"
}

verify_installed() {
  for f in "$AGENT" "$SINGBOX" "$CTL" "$TOKEN_FILE" "$VAR" ${xtcp:+"$FRPC" "$FRPC_CONF" "$FRP_CA"}; do
    trusted "$f" || die "$f is changeable by a non-root user; fix the ownership of its directories and run again"
  done
}

# -- files --------------------------------------------------------------------------------------------------

# Atomic replace: a running binary or script is never written in place.
put() { # put SRC DST MODE
  cp "$1" "$2.new.$$"
  chmod "$3" "$2.new.$$"
  mv -f "$2.new.$$" "$2"
}

install_files() {
  umask 022
  mkdir -p "$PREFIX/bin" "$PREFIX/libexec" "$ETC" "$VAR/agent" "$VAR/sing-box"
  chmod 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/libexec"
  chmod 0700 "$ETC" "$VAR"
  put "$work/ccproxy-exit-agent" "$AGENT" 0755
  if [ -n "$singbox_new" ]; then
    put "$singbox_new" "$SINGBOX" 0755
    printf '%s\n' "$asset_sha" > "$PREFIX/sing-box.sha256"
  fi
  write_ctl > "$work/singbox-ctl"
  put "$work/singbox-ctl" "$CTL" 0755
  if [ -n "$xtcp" ]; then
    if [ -n "$frpc_new" ]; then
      put "$frpc_new" "$FRPC" 0755
      printf '%s\n' "$frpc_sha" > "$PREFIX/frpc.sha256"
    fi
    put "$work/frp-ca.pem" "$FRP_CA" 0644
    # frpc checks the configuration (it names the CA just written) before it replaces the running one.
    if ! out=$("$FRPC" verify -c "$work/frpc.toml" 2>&1); then
      die "frpc rejected the XTCP configuration from the control plane: $out"
    fi
    put "$work/frpc.toml" "$FRPC_CONF" 0600     # frps token and XTCP secret key: root only
  fi
}

write_token() {
  old_umask=$(umask)
  umask 077
  printf '%s\n' "$token" > "$TOKEN_FILE.new.$$"
  chmod 0600 "$TOKEN_FILE.new.$$"
  mv -f "$TOKEN_FILE.new.$$" "$TOKEN_FILE"
  umask "$old_umask"
}

write_conf() {
  {
    echo "# Written by the CC Proxy exit-node installer; reruns reuse these values. No secrets here."
    echo "CP_URL='$cp_url'"
    echo "IFACE='$iface'"
    echo "CAFILE='$cafile'"
    echo "AGENT_NAME='$name'"
    echo "AGENT_VERSION='$AGENT_VERSION'"
    echo "SINGBOX_VERSION='$SINGBOX_VERSION'"
    if [ -n "$xtcp" ]; then echo "TRANSPORT='xtcp'"; else echo "TRANSPORT='public'"; fi
  } > "$CONF_FILE.new.$$"
  chmod 0644 "$CONF_FILE.new.$$"
  mv -f "$CONF_FILE.new.$$" "$CONF_FILE"
}

# Agent command line (one argument per line), shared by the systemd unit and the launchd plist.
agent_args() {
  printf '%s\n' "$AGENT" --cp "$cp_url" --token-file "$TOKEN_FILE" \
    --config "$VAR/config.json" --state-dir "$VAR/agent" --singbox "$SINGBOX" \
    --reload-cmd "$CTL reload" --status-cmd "$CTL status"
  if [ -n "$iface" ]; then printf '%s\n' --iface "$iface"; fi
  if [ -n "$cafile" ]; then printf '%s\n' --cafile "$cafile"; fi
  if [ -n "$name" ]; then printf '%s\n' --name "$name"; fi
}

write_ctl() {
  echo '#!/bin/sh'
  echo '# reload | status for the sing-box service; called by the CC Proxy exit agent. Generated by the installer.'
  if [ "$os" = linux ]; then
    cat <<'EOF'
unit=ccproxy-exit-singbox.service
case ${1:-} in
  reload) exec systemctl reload-or-restart "$unit" ;;   # SIGHUP when running, start after a first config
  status) exec systemctl is-active --quiet "$unit" ;;
  *) echo "usage: $0 reload|status" >&2; exit 2 ;;
esac
EOF
  else
    cat <<'EOF'
target=system/com.ccproxy.exit.singbox
running() { launchctl print "$target" 2>/dev/null | grep -Eq '^[[:space:]]*state = running'; }
case ${1:-} in
  reload) if running; then exec launchctl kill SIGHUP "$target"; else exec launchctl kickstart "$target"; fi ;;
  status) running ;;
  *) echo "usage: $0 reload|status" >&2; exit 2 ;;
esac
EOF
  fi
}

# -- Linux / systemd ----------------------------------------------------------------------------------------

systemd_quote() { printf '"%s"' "$1"; }

install_linux() {
  command -v systemctl >/dev/null 2>&1 || die "systemd is required on Linux"
  if systemctl is-active --quiet sing-box.service 2>/dev/null; then
    say "warning: sing-box.service (another installation) is running; it may hold the same ports"
  fi
  mkdir -p "$SYSTEMD_DIR"
  exec_start=''
  args=$(agent_args)
  while IFS= read -r a; do
    exec_start="$exec_start${exec_start:+ }$(systemd_quote "$a")"
  done <<EOF
$args
EOF
  ips_after='' ips_wants=''
  if [ -n "$iface" ]; then
    ips_after=" ccproxy-exit-ips.service"
    ips_wants="Wants=ccproxy-exit-ips.service"
    cat > "$work/ccproxy-exit-ips.service" <<EOF
# CC Proxy exit node: put the routed egress IPs on $iface at boot, before sing-box. Generated by the installer.
[Unit]
Description=CC Proxy exit node egress IP addresses
After=network-online.target
Wants=network-online.target
Before=ccproxy-exit-singbox.service
ConditionPathExists=$VAR/agent/ips.txt

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$AGENT ips up $iface $VAR/agent/ips.txt
ExecStop=$AGENT ips down $iface $VAR/agent/ips.txt

[Install]
WantedBy=multi-user.target
EOF
    put "$work/ccproxy-exit-ips.service" "$SYSTEMD_DIR/ccproxy-exit-ips.service" 0644
  fi
  cat > "$work/ccproxy-exit-singbox.service" <<EOF
# CC Proxy exit node: sing-box with the last config the agent put in place. Generated by the installer.
[Unit]
Description=CC Proxy exit node sing-box
After=network-online.target$ips_after
Wants=network-online.target
$ips_wants
ConditionPathExists=$VAR/config.json

[Service]
ExecStart=$SINGBOX run -c $VAR/config.json -D $VAR/sing-box
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
  cat > "$work/ccproxy-exit-agent.service" <<EOF
# CC Proxy exit node agent. The token is read from $TOKEN_FILE. Generated by the installer.
[Unit]
Description=CC Proxy exit node agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$exec_start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  put "$work/ccproxy-exit-singbox.service" "$SYSTEMD_DIR/ccproxy-exit-singbox.service" 0644
  put "$work/ccproxy-exit-agent.service" "$SYSTEMD_DIR/ccproxy-exit-agent.service" 0644
  if [ -z "$iface" ] && [ -f "$SYSTEMD_DIR/ccproxy-exit-ips.service" ]; then
    systemctl disable --now ccproxy-exit-ips.service >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DIR/ccproxy-exit-ips.service"
  fi
  if [ -n "$xtcp" ]; then
    cat > "$work/ccproxy-exit-frpc.service" <<EOF
# CC Proxy exit node: frpc registers the XTCP proxy for sing-box with frps. Generated by the installer.
[Unit]
Description=CC Proxy exit node frpc (XTCP, direct only)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$FRPC -c $FRPC_CONF
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    put "$work/ccproxy-exit-frpc.service" "$SYSTEMD_DIR/ccproxy-exit-frpc.service" 0644
  elif [ -f "$SYSTEMD_DIR/ccproxy-exit-frpc.service" ]; then
    remove_frpc_files   # the host moved back to the public entry
  fi
  systemctl daemon-reload
  units="ccproxy-exit-singbox.service ccproxy-exit-agent.service"
  [ -z "$iface" ] || units="ccproxy-exit-ips.service $units"
  [ -z "$xtcp" ] || units="$units ccproxy-exit-frpc.service"
  # shellcheck disable=SC2086
  systemctl enable $units >/dev/null
  if [ -n "$singbox_new" ]; then
    systemctl try-restart ccproxy-exit-singbox.service   # new binary; no-op until a config exists
  fi
  systemctl restart ccproxy-exit-agent.service
  [ -z "$xtcp" ] || systemctl restart ccproxy-exit-frpc.service   # picks up a changed configuration
}

# A host that left the XTCP transport: stop frpc and remove its service, binary and credentials.
remove_frpc_files() {
  if [ "$os" = linux ]; then
    systemctl disable --now ccproxy-exit-frpc.service >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DIR/ccproxy-exit-frpc.service"
  else
    launchctl bootout "system/$MAC_FRPC" >/dev/null 2>&1 || true
    rm -f "$LAUNCHD_DIR/$MAC_FRPC.plist"
  fi
  rm -f "$FRPC" "$PREFIX/frpc.sha256" "$FRPC_CONF" "$FRP_CA"
  say "removed frpc: this host uses the public entry"
}

# -- macOS / launchd ----------------------------------------------------------------------------------------

plist_array() { # one <string> per argument line on stdin
  while IFS= read -r a; do printf '    <string>%s</string>\n' "$a"; done
}

install_macos() {
  mkdir -p "$LAUNCHD_DIR" "$LOGDIR"
  chmod 0755 "$LOGDIR"
  cat > "$work/$MAC_SINGBOX.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- CC Proxy exit node: sing-box with the last config the agent put in place. Generated by the installer. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>$MAC_SINGBOX</string>
  <key>ProgramArguments</key>
  <array>
$(printf '%s\n' "$SINGBOX" run -c "$VAR/config.json" -D "$VAR/sing-box" | plist_array)
  </array>
  <key>KeepAlive</key>
  <dict><key>PathState</key><dict><key>$VAR/config.json</key><true/></dict></dict>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>WorkingDirectory</key><string>$VAR</string>
  <key>StandardOutPath</key><string>$LOGDIR/sing-box.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/sing-box.log</string>
</dict>
</plist>
EOF
  cat > "$work/$MAC_AGENT.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- CC Proxy exit node agent. The token is read from $TOKEN_FILE. Generated by the installer. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>$MAC_AGENT</string>
  <key>ProgramArguments</key>
  <array>
$(agent_args | plist_array)
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGDIR/agent.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/agent.log</string>
</dict>
</plist>
EOF
  if [ -n "$xtcp" ]; then
    cat > "$work/$MAC_FRPC.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- CC Proxy exit node: frpc registers the XTCP proxy for sing-box with frps. Generated by the installer. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>$MAC_FRPC</string>
  <key>ProgramArguments</key>
  <array>
$(printf '%s\n' "$FRPC" -c "$FRPC_CONF" | plist_array)
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGDIR/frpc.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/frpc.log</string>
</dict>
</plist>
EOF
  fi
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$work/$MAC_SINGBOX.plist" "$work/$MAC_AGENT.plist" ${xtcp:+"$work/$MAC_FRPC.plist"} >/dev/null ||
      die "generated plist is invalid"
  fi
  mkdir -p "$NEWSYSLOG_DIR"
  printf '%s\n' "# CC Proxy exit node logs: keep 5 x 10 MB. Generated by the installer." \
    "$LOGDIR/agent.log 644 5 10240 * J" "$LOGDIR/sing-box.log 644 5 10240 * J" \
    ${xtcp:+"$LOGDIR/frpc.log 644 5 10240 * J"} > "$work/newsyslog.conf"
  put "$work/newsyslog.conf" "$NEWSYSLOG_DIR/ccproxy-exit.conf" 0644

  restart_singbox=
  if [ -n "$singbox_new" ] || ! cmp -s "$work/$MAC_SINGBOX.plist" "$LAUNCHD_DIR/$MAC_SINGBOX.plist"; then
    restart_singbox=1
  fi
  for label in $MAC_AGENT ${restart_singbox:+$MAC_SINGBOX}; do
    launchctl bootout "system/$label" >/dev/null 2>&1 || true
  done
  put "$work/$MAC_SINGBOX.plist" "$LAUNCHD_DIR/$MAC_SINGBOX.plist" 0644
  put "$work/$MAC_AGENT.plist" "$LAUNCHD_DIR/$MAC_AGENT.plist" 0644
  if [ -z "$restart_singbox" ] && ! launchctl print "system/$MAC_SINGBOX" >/dev/null 2>&1; then
    restart_singbox=1   # unchanged but not loaded (an earlier run was interrupted)
  fi
  for label in ${restart_singbox:+$MAC_SINGBOX} $MAC_AGENT; do
    launchctl enable "system/$label"
    launchctl bootstrap system "$LAUNCHD_DIR/$label.plist"
  done
  if [ -n "$xtcp" ]; then   # restarted on every run: the configuration may have changed
    launchctl bootout "system/$MAC_FRPC" >/dev/null 2>&1 || true
    put "$work/$MAC_FRPC.plist" "$LAUNCHD_DIR/$MAC_FRPC.plist" 0644
    launchctl enable "system/$MAC_FRPC"
    launchctl bootstrap system "$LAUNCHD_DIR/$MAC_FRPC.plist"
  elif [ -f "$LAUNCHD_DIR/$MAC_FRPC.plist" ]; then
    remove_frpc_files
  fi
}

mac_warnings() {
  fw=/usr/libexec/ApplicationFirewall/socketfilterfw
  if [ -x "$fw" ] && "$fw" --getglobalstate 2>/dev/null | grep -q enabled; then
    say "note: the macOS application firewall is on; allow sing-box to accept connections:"
    say "  sudo $fw --add $SINGBOX && sudo $fw --unblockapp $SINGBOX"
  fi
  if command -v pmset >/dev/null 2>&1 && pmset -g 2>/dev/null | grep -Eq '^[[:space:]]*sleep[[:space:]]+[1-9]'; then
    say "note: this Mac goes to sleep when idle, which stops the exit node; consider: sudo pmset -a sleep 0"
  fi
}

# -- uninstall ----------------------------------------------------------------------------------------------

do_uninstall() {
  if [ "$os" = linux ]; then
    if command -v systemctl >/dev/null 2>&1; then
      # Stopping ccproxy-exit-ips takes the egress IPs off the interface again.
      systemctl disable --now ccproxy-exit-agent.service ccproxy-exit-singbox.service ccproxy-exit-ips.service \
        ccproxy-exit-frpc.service >/dev/null 2>&1 || true
      rm -f "$SYSTEMD_DIR/ccproxy-exit-agent.service" "$SYSTEMD_DIR/ccproxy-exit-singbox.service" \
        "$SYSTEMD_DIR/ccproxy-exit-ips.service" "$SYSTEMD_DIR/ccproxy-exit-frpc.service"
      systemctl daemon-reload || true
    fi
  else
    for label in $MAC_AGENT $MAC_SINGBOX $MAC_FRPC; do
      launchctl bootout "system/$label" >/dev/null 2>&1 || true
      rm -f "$LAUNCHD_DIR/$label.plist"
    done
    rm -f "$NEWSYSLOG_DIR/ccproxy-exit.conf"
    rm -rf "$LOGDIR"
  fi
  rm -rf "$PREFIX" "$ETC" "$VAR"
  say "removed the services, $PREFIX, $ETC (including the agent token and any frpc credentials) and $VAR."
  say "the host still exists in the control plane: rotate its token or delete it in the console."
}

main "$@"
