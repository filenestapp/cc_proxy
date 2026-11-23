"""Exit-node installer assets served by the control plane.

  GET /install/exit.sh                macOS and Linux installer (public: holds no secret)
  GET /install/exit.ps1               Windows installer (public)
  GET /install/manifest.json          agent version and digests, pinned sing-box release (public)
  GET /install/agent/{os}-{arch}      the compiled exit agent (host agent token: the project is private)

Nodes run the compiled Go agent (egress/agent, built reproducibly by egress/agent/build.sh into a dist directory
with SHA256SUMS) and the official sing-box release pinned in egress/install/sing-box.json. Neither Go, Python nor a
repository checkout is needed on the node. Rendering a script replaces its "@@INSTALLER_DATA@@" line with the agent
digests (from SHA256SUMS, each checked against the file it names) and the sing-box digests, so the installer
verifies everything it downloads. install_commands() builds the one-line commands the console shows; the agent
token is never part of them (the installer prompts for it without echo).
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
EGRESS = os.path.join(HERE, "..", "egress")
PINS = os.path.join(EGRESS, "install", "sing-box.json")
DEFAULT_DIST = os.path.join(EGRESS, "agent", "dist")
SCRIPTS = {
    "exit.sh": os.path.join(EGRESS, "install", "exit.sh"),
    "exit.ps1": os.path.join(EGRESS, "install", "exit.ps1"),
}
PLATFORMS = ("darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64")
MARKER = "@@INSTALLER_DATA@@"
PS1_FIRST_LINE = "# CC Proxy exit-node installer for Windows."   # the Windows command runs only a script that starts so
# Used with fullmatch(): "$" alone would also accept a trailing newline, and these values end up in shell commands.
URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?")
IFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")
HEX64 = re.compile(r"[0-9a-f]{64}")
VERSION_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}")


class NotBuilt(Exception):
    """The agent binaries are missing or do not match their SHA256SUMS."""


def load_pins(path=PINS):
    with open(path) as f:
        pins = json.load(f)
    for key, asset in pins["assets"].items():
        if not HEX64.fullmatch(asset["sha256"]) or pins["version"] not in asset["file"]:
            raise ValueError("bad sing-box pin for %s" % key)
    return pins


def dist_dir():
    return os.environ.get("CP_AGENT_DIST") or DEFAULT_DIST


def agent_file(platform):
    return "ccproxy-exit-agent-%s%s" % (platform, ".exe" if platform.startswith("windows") else "")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def agent_release(dist=None):
    """{"version", "digests": {platform: sha256}} of the built agent; every binary is hashed and must match
    SHA256SUMS, so a half-copied or replaced file is never offered to a node."""
    dist = dist or dist_dir()
    try:
        with open(os.path.join(dist, "SHA256SUMS")) as f:
            sums = dict(reversed(line.split()) for line in f if line.strip())
        with open(os.path.join(dist, "VERSION")) as f:
            version = f.read().strip()
    except (OSError, ValueError) as e:
        raise NotBuilt("exit agent binaries are not built (run egress/agent/build.sh): %s" % e)
    if not VERSION_RE.fullmatch(version):
        raise NotBuilt("bad agent VERSION %r" % version)
    digests = {}
    for platform in PLATFORMS:
        name = agent_file(platform)
        want = sums.get(name, "")
        path = os.path.join(dist, name)
        if not HEX64.fullmatch(want) or not os.path.isfile(path) or sha256_file(path) != want:
            raise NotBuilt("%s is missing or does not match SHA256SUMS (rebuild with egress/agent/build.sh)" % name)
        digests[platform] = want
    return {"version": version, "digests": digests}


def agent_path(platform, dist=None):
    if platform not in PLATFORMS:
        raise KeyError(platform)
    return os.path.join(dist or dist_dir(), agent_file(platform))


def base_url(pins):
    return pins["url"].format(version=pins["version"], asset="").rstrip("/")


def manifest(pins=None, dist=None):
    pins = pins or load_pins()
    return {"agent": agent_release(dist),
            "singbox": {"version": pins["version"], "base_url": base_url(pins), "assets": pins["assets"]}}


def _sh_data(pins, release):
    lines = ["# Filled in by the control plane when it serves this script.",
             "AGENT_VERSION='%s'" % release["version"],
             "SINGBOX_VERSION='%s'" % pins["version"], "SINGBOX_BASE_URL='%s'" % base_url(pins),
             "agent_sha256() {", "  case $1 in"]
    lines += ["    %s) echo '%s' ;;" % (k, v) for k, v in sorted(release["digests"].items())]
    lines += ["  esac", "}", "singbox_asset_file() {", "  case $1 in"]
    lines += ["    %s) echo '%s' ;;" % (k, a["file"]) for k, a in sorted(pins["assets"].items())]
    lines += ["  esac", "}", "singbox_asset_sha256() {", "  case $1 in"]
    lines += ["    %s) echo '%s' ;;" % (k, a["sha256"]) for k, a in sorted(pins["assets"].items())]
    lines += ["  esac", "}"]
    return "\n".join(lines)


def _ps_data(pins, release):
    assets = "\n".join("    '%s' = @{ File = '%s'; Sha256 = '%s' }" % (k, a["file"], a["sha256"])
                       for k, a in sorted(pins["assets"].items()))
    agents = "\n".join("    '%s' = '%s'" % (k, v) for k, v in sorted(release["digests"].items()))
    return ("# Filled in by the control plane when it serves this script.\n"
            "$AgentVersion = '%s'\n$AgentSha256 = @{\n%s\n}\n"
            "$SingBoxVersion = '%s'\n$SingBoxBaseUrl = '%s'\n$SingBoxAssets = @{\n%s\n}"
            % (release["version"], agents, pins["version"], base_url(pins), assets))


def render(name, pins=None, dist=None):
    """The installer script `name` with its data block filled in (bytes). Raises NotBuilt without binaries."""
    pins = pins or load_pins()
    release = agent_release(dist)
    with open(SCRIPTS[name], encoding="utf-8") as f:
        text = f.read()
    data = _sh_data(pins, release) if name.endswith(".sh") else _ps_data(pins, release)
    out, n = re.subn(r"^# " + MARKER + r"[ \t]*$", lambda _m: data, text, count=1, flags=re.M)
    if n != 1:
        raise ValueError("%s has no %s line" % (name, MARKER))
    if name.endswith(".ps1"):
        out = out.replace("\r\n", "\n").replace("\n", "\r\n")  # CRLF is native for Windows PowerShell 5.1
    return out.encode("utf-8")


def install_commands(cp, iface=None):
    """One-line install and uninstall commands for each OS; cp is the control plane URL the node will use.

    Only https is accepted, and every command fetches the script with downgrades ruled out (curl -q, so no curlrc
    can change the options, then --proto =https for the request and its redirects; Invoke-RestMethod without
    redirects) into a variable or file first, so a failed or partial download is never handed to sudo or executed.
    The Unix command runs in a subshell that removes the temporary file and still exits with the status of curl or
    the installer, so a failure is reported as one. The token is not part of any command."""
    cp = cp.rstrip("/") if isinstance(cp, str) else ""
    if not URL_RE.fullmatch(cp):
        raise ValueError("cp must be the control plane's https URL, such as https://cp.example:8443 "
                         "(exit nodes send their token to it, so plain http is refused)")
    if iface is not None and not IFACE_RE.fullmatch(iface):
        raise ValueError("iface: invalid interface name")

    def sh(args):
        return ("(f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "
                "'%s/install/exit.sh' -o \"$f\" && sudo sh \"$f\" %s; s=$?; rm -f \"$f\"; exit $s)" % (cp, args))

    def ps(args):
        return ("[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                "$s = Invoke-RestMethod -UseBasicParsing -MaximumRedirection 0 -Uri '%s/install/exit.ps1'; "
                "if ($s -is [string] -and $s.StartsWith('%s')) { & ([scriptblock]::Create($s)) %s } "
                "else { Write-Error 'download failed; nothing was run' }" % (cp, PS1_FIRST_LINE, args))

    return {
        "macos": {"install": sh("--cp '%s'" % cp), "uninstall": sh("--uninstall")},
        "linux": {"install": sh("--cp '%s'" % cp + (" --iface '%s'" % iface if iface else "")),
                  "uninstall": sh("--uninstall")},
        "windows": {"install": ps("-ControlPlane '%s'" % cp), "uninstall": ps("-Uninstall")},
    }
