param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove')][string]$Action
)

$ErrorActionPreference = 'Stop'
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')

try {
    $rawPath = $key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $entries = @()
    if ($null -ne $rawPath -and $rawPath -ne '') {
        $entries = $rawPath.Split(';')
    }
    $directory = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    if ($directory.Contains(';')) {
        throw 'The aifree install path contains a PATH separator.'
    }

    if ($Action -eq 'Add') {
        foreach ($entry in $entries) {
            if ([Environment]::ExpandEnvironmentVariables($entry.Trim('"')).TrimEnd('\') -ieq $directory) {
                return
            }
        }
        $entries = @($entries) + $directory
    } else {
        if (-not ($entries -contains $directory)) {
            return
        }
        $entries = @($entries | Where-Object { $_ -ine $directory })
    }

    $kind = if ($null -eq $rawPath) { [Microsoft.Win32.RegistryValueKind]::ExpandString } else { $key.GetValueKind('Path') }
    $key.SetValue('Path', ($entries -join ';'), $kind)
} finally {
    $key.Dispose()
}
