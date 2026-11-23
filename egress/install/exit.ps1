# CC Proxy exit-node installer for Windows. The control plane serves this file at /install/exit.ps1 with the
# digests below filled in. Copy the command from the console (Egress hosts -> host -> Install command) into
# PowerShell started with "Run as administrator". The command fetches this script over HTTPS without following
# redirects, and runs it only when the download completed and starts with the line above.
#
# The agent token is read with a masked prompt (or from -TokenFile), so it is not in the command line, PowerShell
# history, the task definition or logs. It is stored in C:\ProgramData\CCProxyExit\agent.token, readable by SYSTEM
# and Administrators only. Running the installer again is safe: it upgrades the files and keeps the token when you
# press Enter at the prompt. Enter a new token there after rotating it in the console.
#
# The scheduled task "CCProxyExitAgent" starts at boot as SYSTEM without anyone signing in. The agent supervises
# sing-box (agent.py --run). Windows has no SIGHUP, so a new config is applied by restarting sing-box
# (--run-reload restart); the agent reports a version as applied only after the restarted sing-box is confirmed.
# sing-box starts once the agent has reached the control plane after boot.
#
# First run: install Python 3.8+ from python.org with "Install for all users" (it lands in C:\Program Files and is
# registered under HKLM). A SYSTEM task must not run anything a normal user can change, so the installer refuses an
# interpreter, standard library or install directory that a non-administrator can modify, before running it.
# Program files go to C:\Program Files\CCProxyExit; token, config, state and logs to C:\ProgramData\CCProxyExit.
param(
    [string]$ControlPlane,
    [string]$TokenFile,
    [string]$CaFile,
    [string]$Name,
    [string]$Python,
    [switch]$Uninstall
)

# @@INSTALLER_DATA@@

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$App = Join-Path $env:ProgramFiles 'CCProxyExit'
$Bin = Join-Path $App 'bin'
$Lib = Join-Path $App 'lib'
$Data = Join-Path $env:ProgramData 'CCProxyExit'
$State = Join-Path $Data 'state'
$Logs = Join-Path $Data 'logs'
$TokenPath = Join-Path $Data 'agent.token'
$ConfPath = Join-Path $Data 'install.json'
$SingBoxExe = Join-Path $Bin 'sing-box.exe'
$TaskName = 'CCProxyExitAgent'
$FirewallRule = 'CC Proxy exit node sing-box'
# Full-string patterns: .NET "$" also matches before a trailing newline, "\z" does not.
$UrlPattern = '\Ahttps://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?\z'
$TokenPattern = '\A[A-Za-z0-9_-]{16,256}\z'
$NamePattern = '\A[A-Za-z0-9_.-]{1,64}\z'

function Say([string]$Message) { Write-Host "ccproxy-exit: $Message" }
function Fail([string]$Message) { throw "ccproxy-exit: $Message" }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'run this in PowerShell started with "Run as administrator"'
    }
}

# -- trusted paths --------------------------------------------------------------------------------------------
# SYSTEM, Administrators and TrustedInstaller may change what the task runs; nobody else. On the file and the
# directory holding it any write is refused (a planted DLL or module would run as SYSTEM). Further up, creating new
# entries is tolerated (C:\ lets users create folders) but replacing, deleting or re-permissioning existing ones is not.
$TrustedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$R = [Security.AccessControl.FileSystemRights]
$NearMask = [int]($R::WriteData -bor $R::AppendData -bor $R::WriteExtendedAttributes -bor $R::DeleteSubdirectoriesAndFiles -bor
    $R::Delete -bor $R::ChangePermissions -bor $R::TakeOwnership -bor $R::WriteAttributes) -bor 0x40000000 -bor 0x10000000
$FarMask = [int]($R::DeleteSubdirectoriesAndFiles -bor $R::Delete -bor $R::ChangePermissions -bor $R::TakeOwnership) -bor 0x10000000

function Get-UntrustedAccess([string]$Path, [int]$Mask) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -notcontains $owner) { return "owned by $owner" }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($TrustedSids -contains $rule.IdentityReference.Value) { continue }
        if (([int]$rule.FileSystemRights) -band $Mask) { return "$($rule.IdentityReference.Value) has $($rule.FileSystemRights)" }
    }
    return $null
}

function Assert-Trusted([string]$Path, [string]$Why) {
    $item = Get-Item -LiteralPath $Path -Force
    $near = @($item.FullName)
    if ($item -is [IO.FileInfo]) { $near += $item.DirectoryName }
    $p = $item.FullName
    while ($p) {
        $mask = $FarMask
        if ($near -contains $p) { $mask = $NearMask }
        $problem = Get-UntrustedAccess $p $mask
        if ($problem) { Fail "$p is changeable by a non-administrator ($problem); $Why" }
        $p = Split-Path -Parent $p
    }
}

function Stop-ExitNode {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    # Ending the task does not always end its children: stop our agent and sing-box processes by path.
    $libPattern = [regex]::Escape($Lib)
    Get-CimInstance Win32_Process | Where-Object {
        ($_.ExecutablePath -and $_.ExecutablePath -ieq $SingBoxExe) -or
        ($_.CommandLine -and $_.CommandLine -match $libPattern)
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Remove-ExitNode {
    Stop-ExitNode
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($dir in @($App, $Data)) { if (Test-Path $dir) { Remove-Item -Recurse -Force $dir } }
    Say "removed the scheduled task, the firewall rule, $App and $Data (including the agent token)."
    Say 'the host still exists in the control plane: rotate its token or delete it in the console.'
}

function Find-Python([string]$Requested) {
    # All-users installs registered by the python.org installer; PATH and the Microsoft Store alias are not used.
    $candidates = @()
    if ($Requested) { $candidates += $Requested }
    else {
        foreach ($key in @('HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore')) {
            if (-not (Test-Path $key)) { continue }
            Get-ChildItem $key | Sort-Object { try { [version]$_.PSChildName } catch { [version]'0.0' } } -Descending | ForEach-Object {
                $ip = Join-Path $_.PSPath 'InstallPath'
                if (Test-Path $ip) {
                    $exe = (Get-ItemProperty $ip).'ExecutablePath'
                    if (-not $exe) { $exe = Join-Path (Get-ItemProperty $ip).'(default)' 'python.exe' }
                    $candidates += $exe
                }
            }
        }
    }
    foreach ($exe in $candidates) {
        if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
        $exe = (Resolve-Path -LiteralPath $exe).Path
        $home = Split-Path -Parent $exe
        $why = 'install Python for all users (python.org installer, C:\Program Files) or pass -Python'
        # Checked before it runs even once: the interpreter, its DLLs and its standard library.
        Assert-Trusted $exe $why
        foreach ($sub in @('Lib', 'DLLs')) {
            $dir = Join-Path $home $sub
            if (Test-Path -LiteralPath $dir) { Assert-Trusted $dir $why }
        }
        # -I -S: no environment variables, user site or site-packages hooks.
        try { & $exe -I -S -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>$null } catch { continue }
        if ($LASTEXITCODE -ne 0) { continue }
        return $exe
    }
    Fail ('Python 3.8 or newer installed for all users is required: install it from python.org with ' +
        '"Install for all users" checked, then run the install command again (or pass -Python C:\Program Files\PythonXY\python.exe)')
}

function Read-Token($Existing) {
    $value = ''
    if ($TokenFile) {
        $value = (Get-Content -LiteralPath $TokenFile -TotalCount 1)
    } else {
        $prompt = "Paste the host's agent token"
        if ($Existing) { $prompt += ', or press Enter to keep the installed token' }
        $secure = Read-Host -Prompt $prompt -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    $value = ([string]$value).Trim()
    if (-not $value -and $Existing) { Say 'keeping the installed token'; $value = $Existing }
    if (-not $value) { Fail 'no agent token given' }
    if ($value -notmatch $TokenPattern) { Fail 'that does not look like an agent token (copy it from the console)' }
    return $value
}

# Same helper as the macOS/Linux installer: TLS, downloads and SHA-256 with the Python the agent uses. https only;
# a request carrying the token never follows a redirect. Tokens arrive on stdin, never in the command line.
$HelperPy = @'
import hashlib, os, ssl, sys, urllib.error, urllib.request

def context(cafile):
    return ssl.create_default_context(cafile=None if cafile == "-" else cafile)

class Redirects(urllib.request.HTTPRedirectHandler):
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

def main(cmd, *args):
    if cmd == "check":
        url, cafile = args
        try:
            with request(url + "/agent/probe-targets", cafile, sys.stdin.readline().strip()) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                sys.exit("ccproxy-exit: the control plane rejected the token (rotated or for another control plane?)")
            sys.exit("ccproxy-exit: control plane answered HTTP %d for %s" % (e.code, url))
        except (OSError, ValueError) as e:
            sys.exit("ccproxy-exit: cannot reach %s: %s (private certificate? pass -CaFile)" % (url, e))
    elif cmd == "get":
        url, out, cafile, want, auth = args
        token = sys.stdin.readline().strip() if auth == "token" else None
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
'@

# Copies the agent's output (and sing-box's, which inherits it) to agent.log, keeping 5 files of 10 MB.
$LogPumpPy = @'
import os, sys

path, limit, keep = sys.argv[1], 10 * 1024 * 1024, 5

def rotate():
    for i in range(keep - 1, 0, -1):
        src, dst = "%s.%d" % (path, i), "%s.%d" % (path, i + 1)
        if os.path.exists(src):
            os.replace(src, dst)
    if os.path.exists(path):
        os.replace(path, path + ".1")

out = open(path, "ab")
for line in sys.stdin.buffer:
    out.write(line)
    out.flush()
    if out.tell() > limit:
        out.close()
        rotate()
        out = open(path, "ab")
'@

function Invoke-Helper([string]$Py, [string]$Helper, [string[]]$HelperArgs, [string]$Stdin) {
    $Stdin | & $Py -I -S $Helper @HelperArgs | Out-Host
    return ($LASTEXITCODE -eq 0)
}

function Set-RestrictedAcl([string]$Path, [string]$UsersRead) {
    # SYSTEM and Administrators: full control. Users get read/execute on the program directory only.
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($UsersRead) { $grants += '*S-1-5-32-545:(OI)(CI)RX' }
    & icacls.exe $Path /inheritance:r /grant:r @grants /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "could not restrict access to $Path" }
    & icacls.exe $Path /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
}

function Write-Text([string]$Path, [string]$Text) {
    $tmp = "$Path.new"
    [IO.File]::WriteAllText($tmp, $Text, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Install-ExitNode {
    # Options not given on a rerun keep the values of the existing installation.
    $cp = $ControlPlane; $caFileIn = $CaFile; $agentName = $Name; $pythonIn = $Python
    if (Test-Path $ConfPath) {
        $conf = Get-Content -Raw -LiteralPath $ConfPath | ConvertFrom-Json
        if (-not $cp) { $cp = $conf.ControlPlane }
        if (-not $caFileIn) { $caFileIn = $conf.CaFile }
        if (-not $agentName) { $agentName = $conf.Name }
        if (-not $pythonIn) { $pythonIn = $conf.Python }
    }

    if (-not $cp) { Fail 'pass -ControlPlane https://<control plane>' }
    $cp = ([string]$cp).TrimEnd('/')
    if ($cp -notmatch $UrlPattern) {
        Fail '-ControlPlane must be the https URL of the control plane, such as https://cp.example:8443 (plain http is refused)'
    }
    if ($agentName -and $agentName -notmatch $NamePattern) { Fail "-Name: use letters, digits, '.', '_' or '-'" }
    if ($caFileIn -and -not (Test-Path -LiteralPath $caFileIn -PathType Leaf)) { Fail "-CaFile $caFileIn does not exist" }

    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $assetKey = 'windows-amd64' }
        'ARM64' { $assetKey = 'windows-arm64' }
        default { Fail "unsupported CPU $arch" }
    }
    $asset = $SingBoxAssets[$assetKey]

    $py = Find-Python $pythonIn
    $work = Join-Path ([IO.Path]::GetTempPath()) ('ccproxy-exit-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $helper = Join-Path $work 'helper.py'
        Write-Text $helper $HelperPy
        $existing = $null
        if (Test-Path $TokenPath) { $existing = (Get-Content -LiteralPath $TokenPath -TotalCount 1).Trim() }
        $token = Read-Token $existing
        $ca = '-'
        if ($caFileIn) { $ca = (Resolve-Path -LiteralPath $caFileIn).Path }

        Say 'checking the control plane and the token'
        if (-not (Invoke-Helper $py $helper @('check', $cp, $ca) $token)) { Fail 'nothing was changed' }

        Say 'downloading the agent'
        New-Item -ItemType Directory -Path (Join-Path $work 'lib') | Out-Null
        foreach ($f in @('agent.py', 'probes.py')) {
            $ok = Invoke-Helper $py $helper @('get', "$cp/install/files/$f", (Join-Path $work "lib\$f"), $ca, $AgentFiles[$f], 'token') $token
            if (-not $ok) { Fail "download of $f failed; nothing was changed" }
        }

        $singboxNew = $null
        $marker = Join-Path $Bin 'sing-box.sha256'
        if ((Test-Path $SingBoxExe) -and (Test-Path $marker) -and ((Get-Content -LiteralPath $marker -TotalCount 1) -eq $asset.Sha256)) {
            Say "sing-box $SingBoxVersion already installed"
        } else {
            Say "downloading sing-box $SingBoxVersion ($assetKey)"
            $base = $SingBoxBaseUrl
            if ($env:CCPROXY_EXIT_SINGBOX_BASE_URL) { $base = $env:CCPROXY_EXIT_SINGBOX_BASE_URL }  # still digest-checked
            $zip = Join-Path $work $asset.File
            if (-not (Invoke-Helper $py $helper @('get', "$base/$($asset.File)", $zip, '-', $asset.Sha256, 'none') '')) {
                Fail 'sing-box download failed or its SHA-256 did not match the pinned digest; nothing was changed'
            }
            Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $work 'sb') -Force
            $singboxNew = Join-Path $work ('sb\' + [IO.Path]::GetFileNameWithoutExtension($asset.File) + '\sing-box.exe')
            if (-not (Test-Path $singboxNew)) { Fail "sing-box.exe missing from $($asset.File)" }
        }

        Stop-ExitNode
        foreach ($dir in @($App, $Bin, $Lib, $Data, $State, $Logs)) {
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        }
        Set-RestrictedAcl $App 'users-read'
        Set-RestrictedAcl $Data ''
        foreach ($f in @('agent.py', 'probes.py')) { Copy-Item -LiteralPath (Join-Path $work "lib\$f") -Destination (Join-Path $Lib $f) -Force }
        Write-Text (Join-Path $Lib 'logpump.py') $LogPumpPy
        if ($singboxNew) {
            Copy-Item -LiteralPath $singboxNew -Destination $SingBoxExe -Force
            Write-Text $marker $asset.Sha256
        }
        Write-Text $TokenPath $token
        $token = $null
        $conf = [ordered]@{ ControlPlane = $cp; CaFile = $caFileIn; Name = $agentName; Python = $py; SingBoxVersion = $SingBoxVersion }
        Write-Text $ConfPath ($conf | ConvertTo-Json)

        # -E -s -S: environment variables and site-packages never load code into the SYSTEM agent.
        $agentArgs = @('-E', '-s', '-S', '-u', (Join-Path $Lib 'agent.py'), '--cp', $cp, '--token-file', $TokenPath,
            '--config', (Join-Path $State 'config.json'), '--state-dir', $State, '--singbox', $SingBoxExe,
            '--run', '--run-reload', 'restart')
        if ($caFileIn) { $agentArgs += @('--cafile', $ca) }
        if ($agentName) { $agentArgs += @('--name', $agentName) }
        $quoted = ($agentArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $log = Join-Path $Logs 'agent.log'
        $runCmd = Join-Path $App 'run-agent.cmd'
        $runPs1 = Join-Path $App 'run-agent.ps1'
        Write-Text $runCmd ("@echo off`r`n" +
            "rem CC Proxy exit node agent. The token is read from $TokenPath. Generated by the installer.`r`n" +
            "`"$py`" $quoted 2>&1 | `"$py`" -E -s -S -u `"$(Join-Path $Lib 'logpump.py')`" `"$log`"`r`n")
        # Supervisor loop: clear leftovers of an earlier run, then keep the agent running.
        Write-Text $runPs1 (@"
# CC Proxy exit node: started at boot by the scheduled task $TaskName. Generated by the installer.
`$ErrorActionPreference = 'Continue'
while (`$true) {
    Get-CimInstance Win32_Process | Where-Object { `$_.ExecutablePath -and `$_.ExecutablePath -ieq '$SingBoxExe' } |
        ForEach-Object { Stop-Process -Id `$_.ProcessId -Force -ErrorAction SilentlyContinue }
    & cmd.exe /d /c '$runCmd'
    Start-Sleep -Seconds 5
}
"@)
        Set-RestrictedAcl $App 'users-read'
        Set-RestrictedAcl $Data ''
        foreach ($f in @($py, $SingBoxExe, (Join-Path $Lib 'agent.py'), (Join-Path $Lib 'probes.py'), (Join-Path $Lib 'logpump.py'), $runCmd, $runPs1, $TokenPath)) {
            Assert-Trusted $f 'fix the permissions and run the installer again'
        }

        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runPs1`"")
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description 'CC Proxy exit node agent and sing-box' -Force | Out-Null

        Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Program $SingBoxExe -Action Allow -Profile Any | Out-Null

        Start-ScheduledTask -TaskName $TaskName
        Say 'installed. The host shows a fresh heartbeat in the console within a minute.'
        Say "logs: Get-Content -Wait '$log'"
        Say 'uninstall: copy the Windows uninstall command from the console.'
    } finally {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}

Assert-Admin
if ($Uninstall) { Remove-ExitNode } else { Install-ExitNode }
