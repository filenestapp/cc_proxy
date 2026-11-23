# CC Proxy exit-node installer for Windows. The control plane serves this file at /install/exit.ps1 with the
# digests below filled in. Copy the command from the console (Egress hosts -> host -> Install command) into
# PowerShell started with "Run as administrator". The command fetches this script over HTTPS without following
# redirects, and runs it only when the download completed and starts with the line above.
#
# Nothing has to be installed first. The installer downloads the compiled exit agent from the control plane (with
# the host's token; never across a redirect) and the pinned official sing-box release, and checks both against the
# SHA-256 digests below before anything runs.
#
# The agent token is read with a masked prompt (or from -TokenFile), so it is not in a command line, PowerShell
# history, the task definition or logs. It is stored in C:\ProgramData\CCProxyExit\agent.token, readable by SYSTEM
# and Administrators only. Running the installer again is safe: it upgrades the files and keeps the token when you
# press Enter at the prompt. Enter a new token there after rotating it in the console.
#
# The scheduled task "CCProxyExitAgent" starts ccproxy-exit-agent.exe at boot as SYSTEM, without anyone signing in.
# The agent supervises sing-box (--run). Windows has no SIGHUP, so a new config is applied by restarting sing-box
# (--run-reload restart); the version counts as applied only once the restarted sing-box confirms it. sing-box
# starts once the agent has reached the control plane after boot. Program files go to C:\Program Files\CCProxyExit
# (administrators only); token, config, state and logs to C:\ProgramData\CCProxyExit (SYSTEM and administrators).
# The control plane certificate must be trusted by Windows (a public CA, or a private CA in LocalMachine\Root).
param(
    [string]$ControlPlane,
    [string]$TokenFile,
    [string]$Name,
    [switch]$Uninstall
)

# @@INSTALLER_DATA@@

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$App = Join-Path $env:ProgramFiles 'CCProxyExit'
$Data = Join-Path $env:ProgramData 'CCProxyExit'
$State = Join-Path $Data 'state'
$Logs = Join-Path $Data 'logs'
$AgentExe = Join-Path $App 'ccproxy-exit-agent.exe'
$SingBoxExe = Join-Path $App 'sing-box.exe'
$TokenPath = Join-Path $Data 'agent.token'
$ConfPath = Join-Path $Data 'install.json'
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
# directory holding it any write is refused (a planted DLL would run as SYSTEM). Further up, creating new entries is
# tolerated (C:\ lets users create folders) but replacing, deleting or re-permissioning existing ones is not.
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

function Assert-Trusted([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $near = @($item.FullName)
    if ($item -is [IO.FileInfo]) { $near += $item.DirectoryName }
    $p = $item.FullName
    while ($p) {
        $mask = $FarMask
        if ($near -contains $p) { $mask = $NearMask }
        $problem = Get-UntrustedAccess $p $mask
        if ($problem) { Fail "$p is changeable by a non-administrator ($problem); fix its permissions and run the installer again" }
        $p = Split-Path -Parent $p
    }
}

function Set-RestrictedAcl([string]$Path, [bool]$UsersRead) {
    # SYSTEM and Administrators: full control (owner Administrators). Users may read and run the program files only.
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($UsersRead) { $grants += '*S-1-5-32-545:(OI)(CI)RX' }
    & icacls.exe $Path /inheritance:r /grant:r @grants /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "could not restrict access to $Path" }
    & icacls.exe $Path /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
}

function Stop-ExitNode {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    # Ending the task does not end its children: stop our agent and sing-box processes by path.
    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and (($_.ExecutablePath -ieq $SingBoxExe) -or ($_.ExecutablePath -ieq $AgentExe))
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

# A request to the control plane with the token: https only (checked by the caller), never across a redirect.
function Invoke-ControlPlane([string]$Url, [string]$Token, [string]$OutFile) {
    $params = @{ Uri = $Url; UseBasicParsing = $true; MaximumRedirection = 0; Headers = @{ Authorization = "Bearer $Token" } }
    if ($OutFile) { $params.OutFile = $OutFile }
    try {
        $resp = Invoke-WebRequest @params
        if ($OutFile) { return 200 }
        return [int]$resp.StatusCode
    } catch {
        $r = $null
        if ($_.Exception.PSObject.Properties['Response']) { $r = $_.Exception.Response }
        if ($r) { return [int]$r.StatusCode }
        Fail "cannot reach $Url ($($_.Exception.Message)); nothing was changed"
    }
}

function Test-Sha256([string]$Path, [string]$Want) {
    return ((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -eq $Want)
}

function Write-Text([string]$Path, [string]$Text) {
    $tmp = "$Path.new"
    [IO.File]::WriteAllText($tmp, $Text, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Install-ExitNode {
    # Options not given on a rerun keep the values of the existing installation.
    $cp = $ControlPlane; $agentName = $Name
    if (Test-Path $ConfPath) {
        $conf = Get-Content -Raw -LiteralPath $ConfPath | ConvertFrom-Json
        if (-not $cp) { $cp = $conf.ControlPlane }
        if (-not $agentName) { $agentName = $conf.Name }
    }
    if (-not $cp) { Fail 'pass -ControlPlane https://<control plane>' }
    $cp = ([string]$cp).TrimEnd('/')
    if ($cp -notmatch $UrlPattern) {
        Fail '-ControlPlane must be the https URL of the control plane, such as https://cp.example:8443 (plain http is refused)'
    }
    if ($agentName -and $agentName -notmatch $NamePattern) { Fail "-Name: use letters, digits, '.', '_' or '-'" }

    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $platform = 'windows-amd64' }
        'ARM64' { $platform = 'windows-arm64' }
        default { Fail "unsupported CPU $arch" }
    }
    $asset = $SingBoxAssets[$platform]

    $work = Join-Path ([IO.Path]::GetTempPath()) ('ccproxy-exit-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $existing = $null
        if (Test-Path $TokenPath) { $existing = (Get-Content -LiteralPath $TokenPath -TotalCount 1).Trim() }
        $token = Read-Token $existing

        Say 'checking the control plane and the token'
        $code = Invoke-ControlPlane "$cp/agent/probe-targets" $token $null
        if ($code -eq 401) { Fail 'the control plane rejected the token (rotated, or for another control plane?); nothing was changed' }
        if ($code -ne 200) { Fail "the control plane answered HTTP $code; nothing was changed" }

        Say "downloading ccproxy-exit-agent $AgentVersion ($platform)"
        $agentNew = Join-Path $work 'ccproxy-exit-agent.exe'
        $code = Invoke-ControlPlane "$cp/install/agent/$platform" $token $agentNew
        if ($code -ne 200 -or -not (Test-Sha256 $agentNew $AgentSha256[$platform])) { Fail 'agent download failed or its SHA-256 did not match; nothing was changed' }

        $singboxNew = $null
        $marker = Join-Path $App 'sing-box.sha256'
        if ((Test-Path $SingBoxExe) -and (Test-Path $marker) -and ((Get-Content -LiteralPath $marker -TotalCount 1) -eq $asset.Sha256)) {
            Say "sing-box $SingBoxVersion already installed"
        } else {
            Say "downloading sing-box $SingBoxVersion ($platform)"
            $base = $SingBoxBaseUrl
            if ($env:CCPROXY_EXIT_SINGBOX_BASE_URL) { $base = $env:CCPROXY_EXIT_SINGBOX_BASE_URL }  # still digest-checked
            if (-not $base.StartsWith('https://')) { Fail 'sing-box must be downloaded over https' }
            $zip = Join-Path $work $asset.File
            # GitHub redirects to its CDN; .NET does not follow an https -> http redirect. No token is sent here.
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$($asset.File)" -OutFile $zip
            if (-not (Test-Sha256 $zip $asset.Sha256)) { Fail 'sing-box SHA-256 does not match the pinned digest; nothing was changed' }
            Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $work 'sb') -Force
            $singboxNew = Join-Path $work ('sb\' + [IO.Path]::GetFileNameWithoutExtension($asset.File) + '\sing-box.exe')
            if (-not (Test-Path $singboxNew)) { Fail "sing-box.exe missing from $($asset.File)" }
        }

        Stop-ExitNode
        foreach ($dir in @($App, $Data, $State, $Logs)) {
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        }
        Set-RestrictedAcl $App $true
        Set-RestrictedAcl $Data $false
        Copy-Item -LiteralPath $agentNew -Destination $AgentExe -Force
        if ($singboxNew) {
            Copy-Item -LiteralPath $singboxNew -Destination $SingBoxExe -Force
            Write-Text $marker $asset.Sha256
        }
        Write-Text $TokenPath $token
        $token = $null
        Write-Text $ConfPath (([ordered]@{ ControlPlane = $cp; Name = $agentName; AgentVersion = $AgentVersion; SingBoxVersion = $SingBoxVersion }) | ConvertTo-Json)
        Set-RestrictedAcl $App $true
        Set-RestrictedAcl $Data $false
        foreach ($f in @($AgentExe, $SingBoxExe, $TokenPath, $State)) { Assert-Trusted $f }

        $agentArgs = @('--cp', $cp, '--token-file', $TokenPath, '--config', (Join-Path $State 'config.json'),
            '--state-dir', $State, '--singbox', $SingBoxExe, '--run', '--run-reload', 'restart',
            '--log-file', (Join-Path $Logs 'agent.log'))
        if ($agentName) { $agentArgs += @('--name', $agentName) }
        $argLine = ($agentArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $action = New-ScheduledTaskAction -Execute $AgentExe -Argument $argLine -WorkingDirectory $Data
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description 'CC Proxy exit node agent (supervises sing-box)' -Force | Out-Null

        Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Program $SingBoxExe -Action Allow -Profile Any | Out-Null

        Start-ScheduledTask -TaskName $TaskName
        Say 'installed. The host shows a fresh heartbeat in the console within a minute.'
        Say "logs: Get-Content -Wait '$(Join-Path $Logs 'agent.log')'"
        Say 'uninstall: copy the Windows uninstall command from the console.'
    } finally {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}

Assert-Admin
if ($Uninstall) { Remove-ExitNode } else { Install-ExitNode }
