"""Exit-node installer assets served by the control plane.

  GET /install/exit.sh           macOS and Linux installer (public: holds no secret)
  GET /install/exit.ps1          Windows installer (public)
  GET /install/manifest.json     pinned sing-box release and the digests of the agent files (public)
  GET /install/files/{name}      agent.py, probes.py, ips.sh (agent token: the project's code is not public)

The scripts are templates in egress/install/. Rendering replaces the "@@INSTALLER_DATA@@" line with the pinned
sing-box version, its per-platform SHA-256 digests (egress/install/sing-box.json) and the SHA-256 of each agent file
as served now, so an installer verifies everything it downloads. install_commands() builds the one-line commands
the console shows; the agent token is never part of them (the installer prompts for it without echo).
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
EGRESS = os.path.join(HERE, "..", "egress")
PINS = os.path.join(EGRESS, "install", "sing-box.json")
SCRIPTS = {
    "exit.sh": os.path.join(EGRESS, "install", "exit.sh"),
    "exit.ps1": os.path.join(EGRESS, "install", "exit.ps1"),
}
FILES = {
    "agent.py": os.path.join(HERE, "agent.py"),
    "probes.py": os.path.join(HERE, "probes.py"),
    "ips.sh": os.path.join(EGRESS, "deploy", "ips.sh"),
}
MARKER = "@@INSTALLER_DATA@@"
PS1_FIRST_LINE = "# CC Proxy exit-node installer for Windows."   # the Windows command runs only a script that starts so
# Used with fullmatch(): "$" alone would also accept a trailing newline, and these values end up in shell commands.
URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?")
IFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def load_pins(path=PINS):
    with open(path) as f:
        pins = json.load(f)
    for key, asset in pins["assets"].items():
        if not HEX64.fullmatch(asset["sha256"]) or pins["version"] not in asset["file"]:
            raise ValueError("bad sing-box pin for %s" % key)
    return pins


def read_file(name):
    with open(FILES[name], "rb") as f:
        return f.read()


def file_digests():
    return {name: hashlib.sha256(read_file(name)).hexdigest() for name in FILES}


def base_url(pins):
    return pins["url"].format(version=pins["version"], asset="").rstrip("/")


def manifest(pins=None):
    pins = pins or load_pins()
    return {"singbox": {"version": pins["version"], "base_url": base_url(pins), "assets": pins["assets"]},
            "files": file_digests()}


def _sh_data(pins):
    lines = ["# Filled in by the control plane when it serves this script.",
             "SINGBOX_VERSION='%s'" % pins["version"], "SINGBOX_BASE_URL='%s'" % base_url(pins),
             "singbox_asset_file() {", "  case $1 in"]
    lines += ["    %s) echo '%s' ;;" % (k, a["file"]) for k, a in sorted(pins["assets"].items())]
    lines += ["  esac", "}", "singbox_asset_sha256() {", "  case $1 in"]
    lines += ["    %s) echo '%s' ;;" % (k, a["sha256"]) for k, a in sorted(pins["assets"].items())]
    lines += ["  esac", "}", "file_sha256() {", "  case $1 in"]
    lines += ["    %s) echo '%s' ;;" % (k, v) for k, v in sorted(file_digests().items())]
    lines += ["  esac", "}"]
    return "\n".join(lines)


def _ps_data(pins):
    assets = "\n".join("    '%s' = @{ File = '%s'; Sha256 = '%s' }" % (k, a["file"], a["sha256"])
                       for k, a in sorted(pins["assets"].items()))
    files = "\n".join("    '%s' = '%s'" % (k, v) for k, v in sorted(file_digests().items()))
    return ("# Filled in by the control plane when it serves this script.\n"
            "$SingBoxVersion = '%s'\n$SingBoxBaseUrl = '%s'\n$SingBoxAssets = @{\n%s\n}\n$AgentFiles = @{\n%s\n}"
            % (pins["version"], base_url(pins), assets, files))


def render(name, pins=None):
    """The installer script `name` with its data block filled in (bytes)."""
    pins = pins or load_pins()
    with open(SCRIPTS[name], encoding="utf-8") as f:
        text = f.read()
    data = _sh_data(pins) if name.endswith(".sh") else _ps_data(pins)
    out, n = re.subn(r"^# " + MARKER + r"\s*$", lambda _m: data, text, count=1, flags=re.M)
    if n != 1:
        raise ValueError("%s has no %s line" % (name, MARKER))
    if name.endswith(".ps1"):
        out = out.replace("\r\n", "\n").replace("\n", "\r\n")  # Windows PowerShell 5.1 reads either; CRLF is native
    return out.encode("utf-8")


def install_commands(cp, iface=None):
    """One-line install and uninstall commands for each OS; cp is the control plane URL the node will use.

    Only https is accepted, and every command fetches the script with downgrades ruled out (curl --proto =https
    for the request and its redirects; Invoke-RestMethod without redirects) into a variable or file first, so a
    failed or partial download is never handed to sudo or executed. The token is not part of any command."""
    cp = cp.rstrip("/") if isinstance(cp, str) else ""
    if not URL_RE.fullmatch(cp):
        raise ValueError("cp must be the control plane's https URL, such as https://cp.example:8443 "
                         "(exit nodes send their token to it, so plain http is refused)")
    if iface is not None and not IFACE_RE.fullmatch(iface):
        raise ValueError("iface: invalid interface name")

    def sh(args):
        return ("f=$(mktemp) && curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL '%s/install/exit.sh' "
                "-o \"$f\" && sudo sh \"$f\" %s; rm -f \"$f\"" % (cp, args))

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
