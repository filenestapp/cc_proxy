$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$route = Find-NetRoute -RemoteIPAddress '1.1.1.1' |
    Where-Object { $_.PSObject.Properties['NextHop'] } | Select-Object -First 1
$preferred = if ($route) { Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex | Select-Object -First 1 }
$dns = if ($route) { (Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex).ServerAddresses }
$addresses = @(Get-NetIPAddress)
$adapters = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object ConnectionState -eq 'Connected' | ForEach-Object {
    $index = $_.InterfaceIndex
    @{
        name = [string]$_.InterfaceAlias
        mtu = [uint32]$_.NlMtu
        addresses = @($addresses | Where-Object InterfaceIndex -eq $index | ForEach-Object { [string]$_.IPAddress })
    }
})
$internet = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$proxy = if ($internet.ProxyEnable) { [string]$internet.ProxyServer }
@{
    version = if ($version.CurrentBuild) { "Windows build $($version.CurrentBuild)" } else { 'Windows' }
    interface = if ($route) { [string]$route.InterfaceAlias }
    gateway = if ($route) { [string]$route.NextHop }
    mtu = if ($preferred) { [uint32]$preferred.NlMtu }
    dns = @($dns | Where-Object { $_ })
    tunnels = $adapters
    proxy = $proxy
    pac = $internet.AutoConfigURL
} | ConvertTo-Json -Depth 5 -Compress
