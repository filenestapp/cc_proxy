#!/bin/sh
# CC Proxy exit-node installer for macOS and Linux. The control plane serves this file at /install/exit.sh with
# the digests below filled in; copy the command from the console (Egress hosts -> host -> Install command). It
# downloads over HTTPS only (no redirect may downgrade it) into a file first, so a failed download never reaches sudo:
#
#   f=$(mktemp) && curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL 'https://cp.example/install/exit.sh' \
#     -o "$f" && sudo sh "$f" --cp 'https://cp.example' [--iface eth0]; rm -f "$f"
#   (same with --uninstall instead of --cp ...)
#
# The agent runs as root, so it only runs a trusted system Python: every path component of the interpreter, its
# standard library and the installed files must be owned by root and writable by nobody else. The defaults are
# Apple's Command Line Tools Python on macOS (install it first with `xcode-select --install`) and /usr/bin/python3 on
# Linux. The agent starts with -E -s -S, so environment variables and site-packages never load code into it.
#
# The host's agent token is read from the terminal without echo (or from --token-file), so it never appears in the
# command line, shell history, process list, service definitions or logs. It is stored in
# /etc/ccproxy-exit/agent.token (root, 0600). Running the installer again is safe: it upgrades the files, keeps the
# last configuration and, when you press Enter at the token prompt, the existing token. Enter a new token there after
# rotating it in the console.
#
# What it installs:
#   /opt/ccproxy-exit/lib/{agent.py,probes.py,ips.sh}   agent from the control plane (SHA-256 checked)
#   /opt/ccproxy-exit/bin/sing-box                        pinned official release (SHA-256 checked)
#   /opt/ccproxy-exit/libexec/singbox-ctl                 reload / status helper the agent calls
#   /etc/ccproxy-exit/{agent.token,install.conf}          token (0600) and the options of this installation
#   /var/lib/ccproxy-exit/                                sing-box config written by the agent, state (0700)
#   Linux: systemd units ccproxy-exit-singbox, ccproxy-exit-agent and, with --iface, ccproxy-exit-ips
#   macOS: launchd daemons com.ccproxy.exit.singbox and com.ccproxy.exit.agent; logs in /var/log/ccproxy-exit
# Both start at boot without anyone logging in. sing-box starts from the last applied config even when the control
# plane is unreachable; the agent keeps it in step once it can reach the control plane.
#
# Options:
#   --cp URL           control plane base URL (https). Remembered for reruns.
#   --iface IFACE      Linux only: add the host's routed egress IPs to IFACE (ips.sh). Remembered; --no-iface drops it.
#   --token-file FILE  read the agent token from FILE instead of prompting (for automation)
#   --cafile FILE      CA bundle when the control plane uses a private certificate. Remembered.
#   --name NAME        agent name in its logs (default: the hostname). Remembered.
#   --python PATH      root-owned Python 3.8+ for the agent (default: /Library/Developer/CommandLineTools/usr/bin/
#                      python3 on macOS, /usr/bin/python3 on Linux). Remembered.
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
TOKEN_FILE=$ETC/agent.token
CONF_FILE=$ETC/install.conf
MAC_SINGBOX=com.ccproxy.exit.singbox
MAC_AGENT=com.ccproxy.exit.agent
NL='
'

say() { printf '%s\n' "$PROG: $*" >&2; }
die() { say "error: $*"; exit 1; }

# valid REGEX VALUE: VALUE is a single line that matches the extended regex.
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
usage: sudo sh exit.sh --cp https://<cp> [--iface IFACE | --no-iface] [--token-file FILE] [--cafile FILE]
                        [--name NAME] [--python PATH]
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
  cp_url='' iface='' token_src='' cafile='' name='' python='' uninstall='' no_iface=''
  while [ $# -gt 0 ]; do
    case $1 in
      --cp) [ $# -ge 2 ] || usage; cp_url=$2; shift 2 ;;
      --iface) [ $# -ge 2 ] || usage; iface=$2; shift 2 ;;
      --no-iface) no_iface=1; shift ;;
      --token-file) [ $# -ge 2 ] || usage; token_src=$2; shift 2 ;;
      --cafile) [ $# -ge 2 ] || usage; cafile=$2; shift 2 ;;
      --name) [ $# -ge 2 ] || usage; name=$2; shift 2 ;;
      --python) [ $# -ge 2 ] || usage; python=$2; shift 2 ;;
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
    *) die "unsupported system $os (macOS and Linux only; use exit.ps1 on Windows)" ;;
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
  [ -n "$python" ] || python=$(conf_get PYTHON)

  [ -n "$cp_url" ] || die "pass --cp https://<control plane>"
  cp_url=${cp_url%/}
  valid "$RE_URL" "$cp_url" || die "--cp must be a plain URL such as https://cp.example:8443"
  case $cp_url in
    https://*) ;;
    *) die "--cp must use https: the agent token must not cross the network in clear text" ;;
  esac
  if [ -n "$iface" ]; then
    [ "$os" = linux ] || die "--iface is Linux-only. On macOS the Mac's existing local IPv4 is the egress IP; add that address to the host in the console."
    valid "$RE_IFACE" "$iface" || die "--iface: invalid interface name"
  fi
  [ -z "$name" ] || valid "$RE_NAME" "$name" || die "--name: use letters, digits, '.', '_' or '-'"
  if [ -n "$cafile" ]; then
    valid "$RE_PATH" "$cafile" && [ -f "$cafile" ] || die "--cafile must be an existing absolute path"
  fi

  case ${CCPROXY_EXIT_TEST_ARCH:-$(uname -m)} in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=amd64 ;;
    *) die "unsupported CPU $(uname -m)" ;;
  esac
  asset_key=$os-$arch
  asset_file=$(singbox_asset_file "$asset_key")
  asset_sha=$(singbox_asset_sha256 "$asset_key")
  [ -n "$asset_file" ] && [ -n "$asset_sha" ] || die "no pinned sing-box build for $asset_key"

  find_python
  # In sticky /tmp, not the caller's $TMPDIR: an unprivileged owner of the parent could swap a root-owned work dir.
  mkdir -p "$ROOT/tmp"
  work=$(mktemp -d "$ROOT/tmp/ccproxy-exit.XXXXXX")
  write_helper

  read_token
  say "checking the control plane and the token"
  if ! printf '%s\n' "$token" | "$python" -I -S "$work/helper.py" check "$cp_url" "${cafile:--}"; then
    die "nothing was changed"
  fi

  say "downloading the agent"
  mkdir -p "$work/lib"
  for f in agent.py probes.py ips.sh; do
    printf '%s\n' "$token" | "$python" -I -S "$work/helper.py" get "$cp_url/install/files/$f" "$work/lib/$f" "${cafile:--}" \
      "$(file_sha256 "$f")" token || die "download of $f failed; nothing was changed"
  done

  singbox_new=
  if [ -x "$PREFIX/bin/sing-box" ] && [ "$(cat "$PREFIX/sing-box.sha256" 2>/dev/null || true)" = "$asset_sha" ]; then
    say "sing-box $SINGBOX_VERSION already installed"
  else
    say "downloading sing-box $SINGBOX_VERSION ($asset_key)"
    base=${CCPROXY_EXIT_SINGBOX_BASE_URL:-$SINGBOX_BASE_URL}   # a mirror still has to match the pinned digest
    "$python" -I -S "$work/helper.py" get "$base/$asset_file" "$work/$asset_file" - "$asset_sha" none </dev/null ||
      die "sing-box download failed or its SHA-256 did not match the pinned digest; nothing was changed"
    mkdir -p "$work/sb"
    tar -xzf "$work/$asset_file" -C "$work/sb"
    dir=${asset_file%.tar.gz}
    [ -f "$work/sb/$dir/sing-box" ] || die "sing-box binary missing from $asset_file"
    singbox_new=$work/sb/$dir/sing-box
  fi

  install_files
  write_token
  write_conf
  verify_installed
  if [ "$os" = linux ]; then install_linux; else install_macos; fi
  token=

  say "installed. The host shows a fresh heartbeat in the console within a minute."
  if [ "$os" = linux ]; then
    say "logs: journalctl -u ccproxy-exit-agent -u ccproxy-exit-singbox -f"
  else
    say "logs: tail -f $LOGDIR/agent.log $LOGDIR/sing-box.log"
    mac_warnings
  fi
  say "uninstall: copy the uninstall command from the console, or run this script again with --uninstall"
}

# -- trusted paths ------------------------------------------------------------------------------------------
# A root daemon must not run anything a normal user can change: each path component, up to /, must be owned by root
# and not writable by group (unless group 0) or others, with no ACL. Symlinks are checked and then followed.

TEST_TRUSTED_UID=${CCPROXY_EXIT_TEST_TRUSTED_UID:-}   # tests only: also trust this uid, for paths under $ROOT

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

# shellcheck disable=SC2012  # ls -ldn is the portable owner/mode query on both macOS and Linux
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

find_python() {
  if [ -z "$python" ]; then
    if [ "$os" = darwin ]; then python=/Library/Developer/CommandLineTools/usr/bin/python3; else python=/usr/bin/python3; fi
  fi
  case $python in /*) ;; *) die "--python must be an absolute path" ;; esac
  valid "$RE_PATH" "$python" || die "--python: unsupported characters in the path"
  if [ ! -x "$python" ]; then
    if [ "$os" = darwin ]; then
      die "the agent needs Apple's Command Line Tools Python ($python). Install the Command Line Tools with
  xcode-select --install
(or 'Command Line Tools for Xcode' from developer.apple.com), then run the install command again."
    fi
    die "the agent needs the system Python 3.8+ at $python (e.g. apt install python3 or dnf install python3)"
  fi
  if [ "$os" = darwin ] && [ "$(resolve "$python")" = /usr/bin/python3 ]; then
    die "/usr/bin/python3 only forwards to the developer tools xcode-select picks; use --python /Library/Developer/CommandLineTools/usr/bin/python3"
  fi
  # Check before running it even once as root: the interpreter, and the prefix that holds its standard library.
  trusted "$python" || die "$python is changeable by a non-root user; a root daemon must not run it. Use the system Python (see --python)."
  prefix=$(dirname "$(dirname "$(resolve "$python")")")
  for d in "$prefix" "$prefix/lib"; do
    [ ! -e "$d" ] || trusted "$d" || die "$d is changeable by a non-root user; use the system Python (see --python)"
  done
  # -I -S: no environment variables, current directory, user site or site-packages hooks.
  info=$("$python" -I -S -c 'import sys, sysconfig
if sys.version_info < (3, 8): sys.exit(3)
paths = sysconfig.get_paths()
print(sys.executable); print(paths["stdlib"]); print(paths["platstdlib"])') || die "$python is not Python 3.8 or newer"
  while IFS= read -r d; do
    [ -z "$d" ] || [ ! -e "$d" ] || trusted "$d" ||
      die "$d (used by $python) is changeable by a non-root user; use the system Python (see --python)"
  done <<EOF
$info
EOF
}

verify_installed() {
  for f in "$PREFIX/bin/sing-box" "$PREFIX/lib/agent.py" "$PREFIX/lib/probes.py" "$PREFIX/lib/ips.sh" \
    "$PREFIX/libexec/singbox-ctl" "$TOKEN_FILE" "$VAR"; do
    trusted "$f" || die "$f is changeable by a non-root user; fix the ownership of its directories and run again"
  done
}

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

# Python helper: TLS, downloads and SHA-256 with the interpreter the agent uses, so certificate problems surface
# here and not in the service. Tokens arrive on stdin, never in argv.
write_helper() {
  cat > "$work/helper.py" <<'PY'
import hashlib, os, ssl, sys, urllib.error, urllib.request

def context(cafile):
    return ssl.create_default_context(cafile=None if cafile == "-" else cafile)

class Redirects(urllib.request.HTTPRedirectHandler):
    """The token never follows a redirect, and nothing is fetched over plain http."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.has_header("Authorization"):
            raise urllib.error.URLError("refused redirect to %s: the agent token is sent to the control plane URL only" % newurl)
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("refused redirect to %s: not https" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def request(url, cafile, token):
    if not url.lower().startswith("https://"):
        raise ValueError("refusing a non-https URL")
    req = urllib.request.Request(url, headers={"User-Agent": "ccproxy-exit-installer"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context(cafile)), Redirects())
    return opener.open(req, timeout=60)

def token_from_stdin():
    return sys.stdin.readline().strip()

def main(cmd, *args):
    if cmd == "check":
        url, cafile = args
        try:
            with request(url + "/agent/probe-targets", cafile, token_from_stdin()) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                sys.exit("ccproxy-exit: the control plane rejected the token (rotated or for another control plane?)")
            sys.exit("ccproxy-exit: control plane answered HTTP %d for %s" % (e.code, url))
        except (OSError, ValueError) as e:
            sys.exit("ccproxy-exit: cannot reach %s: %s (private certificate? pass --cafile)" % (url, e))
    elif cmd == "get":
        url, out, cafile, want, auth = args
        token = token_from_stdin() if auth == "token" else None
        digest = hashlib.sha256()
        try:
            with request(url, cafile, token) as resp, open(out, "wb") as f:
                for chunk in iter(lambda: resp.read(1 << 16), b""):
                    digest.update(chunk)
                    f.write(chunk)
        except (OSError, ValueError) as e:
            sys.exit("ccproxy-exit: download of %s failed: %s" % (url, e))
        if digest.hexdigest() != want:
            os.unlink(out)
            sys.exit("ccproxy-exit: SHA-256 mismatch for %s: want %s, got %s" % (url, want, digest.hexdigest()))
    else:
        sys.exit("unknown helper command")

main(*sys.argv[1:])
PY
}

# Atomic replace: a running binary or script is never written in place.
put() { # put SRC DST MODE
  cp "$1" "$2.new.$$"
  chmod "$3" "$2.new.$$"
  mv -f "$2.new.$$" "$2"
}

install_files() {
  umask 022
  mkdir -p "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/libexec" "$ETC" "$VAR"
  chmod 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/libexec"
  chmod 0700 "$ETC" "$VAR"
  put "$work/lib/agent.py" "$PREFIX/lib/agent.py" 0644
  put "$work/lib/probes.py" "$PREFIX/lib/probes.py" 0644
  put "$work/lib/ips.sh" "$PREFIX/lib/ips.sh" 0755
  if [ -n "$singbox_new" ]; then
    put "$singbox_new" "$PREFIX/bin/sing-box" 0755
    printf '%s\n' "$asset_sha" > "$PREFIX/sing-box.sha256"
  fi
  write_ctl > "$work/singbox-ctl"
  put "$work/singbox-ctl" "$PREFIX/libexec/singbox-ctl" 0755
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
    echo "PYTHON='$python'"
    echo "SINGBOX_VERSION='$SINGBOX_VERSION'"
  } > "$CONF_FILE.new.$$"
  chmod 0644 "$CONF_FILE.new.$$"
  mv -f "$CONF_FILE.new.$$" "$CONF_FILE"
}

# Arguments for agent.py (one per line), shared by the systemd unit and the launchd plist.
agent_args() {
  printf '%s\n' "$PREFIX/lib/agent.py" --cp "$cp_url" --token-file "$TOKEN_FILE" \
    --config "$VAR/config.json" --state-dir "$VAR" --singbox "$PREFIX/bin/sing-box" \
    --reload-cmd "$PREFIX/libexec/singbox-ctl reload" --status-cmd "$PREFIX/libexec/singbox-ctl status"
  if [ -n "$iface" ]; then printf '%s\n' --iface "$iface" --ips-script "$PREFIX/lib/ips.sh"; fi
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
  exec_start="$(systemd_quote "$python") -E -s -S"
  args=$(agent_args)
  while IFS= read -r a; do
    exec_start="$exec_start $(systemd_quote "$a")"
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
ConditionPathExists=$VAR/ips.txt

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh $PREFIX/lib/ips.sh up $iface $VAR/ips.txt
ExecStop=/bin/sh $PREFIX/lib/ips.sh down $iface $VAR/ips.txt

[Install]
WantedBy=multi-user.target
EOF
    put "$work/ccproxy-exit-ips.service" "$SYSTEMD_DIR/ccproxy-exit-ips.service" 0644
  fi
  cat > "$work/ccproxy-exit-singbox.service" <<EOF
# CC Proxy exit node: sing-box with the last config the agent applied. Generated by the installer.
[Unit]
Description=CC Proxy exit node sing-box
After=network-online.target$ips_after
Wants=network-online.target
$ips_wants
ConditionPathExists=$VAR/config.json

[Service]
ExecStart=$PREFIX/bin/sing-box run -c $VAR/config.json -D $VAR
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
# CC Proxy exit node: control-plane agent. The token is read from $TOKEN_FILE. Generated by the installer.
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
  systemctl daemon-reload
  units="ccproxy-exit-singbox.service ccproxy-exit-agent.service"
  [ -z "$iface" ] || units="ccproxy-exit-ips.service $units"
  # shellcheck disable=SC2086
  systemctl enable $units >/dev/null
  if [ -n "$singbox_new" ]; then
    systemctl try-restart ccproxy-exit-singbox.service   # new binary; no-op until a config exists
  fi
  systemctl restart ccproxy-exit-agent.service
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
<!-- CC Proxy exit node: sing-box with the last config the agent applied. Generated by the installer. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>$MAC_SINGBOX</string>
  <key>ProgramArguments</key>
  <array>
$(printf '%s\n' "$PREFIX/bin/sing-box" run -c "$VAR/config.json" -D "$VAR" | plist_array)
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
$({ printf '%s\n' "$python" -E -s -S; agent_args; } | plist_array)
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
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$work/$MAC_SINGBOX.plist" "$work/$MAC_AGENT.plist" >/dev/null || die "generated plist is invalid"
  fi
  mkdir -p "$NEWSYSLOG_DIR"
  printf '%s\n' "# CC Proxy exit node logs: keep 5 x 10 MB. Generated by the installer." \
    "$LOGDIR/agent.log 644 5 10240 * J" "$LOGDIR/sing-box.log 644 5 10240 * J" > "$work/newsyslog.conf"
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
}

mac_warnings() {
  fw=/usr/libexec/ApplicationFirewall/socketfilterfw
  if [ -x "$fw" ] && "$fw" --getglobalstate 2>/dev/null | grep -q enabled; then
    say "note: the macOS application firewall is on; allow sing-box to accept connections:"
    say "  sudo $fw --add $PREFIX/bin/sing-box && sudo $fw --unblockapp $PREFIX/bin/sing-box"
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
        >/dev/null 2>&1 || true
      rm -f "$SYSTEMD_DIR/ccproxy-exit-agent.service" "$SYSTEMD_DIR/ccproxy-exit-singbox.service" \
        "$SYSTEMD_DIR/ccproxy-exit-ips.service"
      systemctl daemon-reload || true
    fi
  else
    for label in $MAC_AGENT $MAC_SINGBOX; do
      launchctl bootout "system/$label" >/dev/null 2>&1 || true
      rm -f "$LAUNCHD_DIR/$label.plist"
    done
    rm -f "$NEWSYSLOG_DIR/ccproxy-exit.conf"
    rm -rf "$LOGDIR"
  fi
  rm -rf "$PREFIX" "$ETC" "$VAR"
  say "removed the services, $PREFIX, $ETC (including the agent token) and $VAR."
  say "the host still exists in the control plane: rotate its token or delete it in the console."
}

main "$@"
