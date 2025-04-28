<#
.SYNOPSIS
  Network utility menu with enhanced filtering and automation options.
.PARAMETER NoMenu
  Run a single command and exit without interactive menu.
.PARAMETER NoResolve
  Skip reverse DNS lookups for faster outbound connection display.
.PARAMETER OutputCSV
  When used with NoMenu, exports output to CSV.
.PARAMETER OutputJSON
  When used with NoMenu, outputs JSON.
#>
param(
    [switch]$NoMenu,
    [switch]$NoResolve,
    [switch]$OutputCSV,
    [switch]$OutputJSON
)

# Global DNS cache to avoid repeated lookups
$Global:DnsCache = @{}

function Show-Menu {
    Clear-Host
    Write-Host "Select an option:`n"
    Write-Host "1) Show My Network Interfaces"
    Write-Host "2) Show Devices Seen (ARP Table)"
    Write-Host "3) Show Outbound Connections"
    Write-Host "4) Exit"
    $choice = Read-Host "Enter selection (1-4)"
    switch ($choice) {
        '1' { Show-NetworkInterfaces }
        '2' { Show-ARPTable }
        '3' {
            # Ask whether to skip reverse DNS
            $skipInput = Read-Host "Skip reverse DNS lookups for faster output? (Y/N)"
            $skip = $skipInput -match '^[Yy]'
            if ($skip) {
                Show-OutboundConnections -NoResolve
            } else {
                Show-OutboundConnections
            }
        }
        '4' { Write-Host "Exiting..."; return }
        default { Write-Host "Invalid selection. Please choose 1-4." }
    }
    Write-Host
    Read-Host "Press Enter to return to the menu"
    Show-Menu
}

function Show-NetworkInterfaces {
    [CmdletBinding()]
    param(
        [string]$InterfaceAlias
    )
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { -not $InterfaceAlias -or $_.InterfaceAlias -eq $InterfaceAlias }
    if (!$ips) { Write-Host "No matching IPv4 addresses found."; return }
    $results = $ips | ForEach-Object {
        $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Interface  = $_.InterfaceAlias
            IPAddress  = $_.IPAddress
            MACAddress = if ($adapter) { $adapter.MacAddress } else { 'N/A' }
        }
    }
    $results | Format-Table -AutoSize
}

function Show-ARPTable {
    [CmdletBinding()]
    param(
        [switch]$IncludeLinkLocal,
        [string]$InterfaceAlias
    )
    $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Invalid' } |
        Where-Object {
            ($IncludeLinkLocal -or ($_.IPAddress -notmatch '^fe80:')) -and
            (-not $InterfaceAlias -or $_.InterfaceAlias -eq $InterfaceAlias)
        }
    if (!$neighbors) { Write-Host "No ARP entries found."; return }
    $neighbors |
        Select-Object InterfaceAlias,
            @{Name='IPAddress';Expression={$_.IPAddress}},
            @{Name='MACAddress';Expression={$_.LinkLayerAddress}} |
        Format-Table -AutoSize
}

function Resolve-Hostname {
    param(
        [string]$IP,
        [int]$TimeoutSec = 1
    )
    if ($Global:DnsCache.ContainsKey($IP)) { return $Global:DnsCache[$IP] }
    if ($IP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
        $Global:DnsCache[$IP] = $IP; return $IP
    }
    $resolvedHost = $IP
    try {
        $job = Start-Job -ScriptBlock { param($addr) [System.Net.Dns]::GetHostEntry($addr).HostName } -ArgumentList $IP
        if (Wait-Job $job -Timeout $TimeoutSec) { $resolvedHost = Receive-Job $job -ErrorAction SilentlyContinue }
        Remove-Job $job -Force
    } catch {
        # fallback remains IP
    }
    $Global:DnsCache[$IP] = $resolvedHost
    return $resolvedHost
}

function Show-OutboundConnections {
    [CmdletBinding()]
    param(
        [switch]$NoResolve,
        [string] $ProcessName,
        [int[]]  $RemotePort,
        [string] $RemoteSubnet
    )
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if ($ProcessName)  { $conns = $conns | Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -eq $ProcessName } }
    if ($RemotePort)   { $conns = $conns | Where-Object { $RemotePort -contains $_.RemotePort } }
    if ($RemoteSubnet) { $conns = $conns | Where-Object { $_.RemoteAddress -like "$RemoteSubnet*" } }
    if (!$conns) { Write-Host "No outbound connections matching criteria found."; return }

    $results = $conns | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $pname = if ($proc) { $proc.ProcessName } else { 'Unknown' }
        if ($NoResolve) {
            $hostDisplay = $_.RemoteAddress
        } else {
            $hostDisplay = Resolve-Hostname -IP $_.RemoteAddress
        }
        [PSCustomObject]@{
            Process         = $pname
            'Local Address' = "$($_.LocalAddress):$($_.LocalPort)"
            'Remote Address'= "$($hostDisplay):$($_.RemotePort)"
        }
    }
    if ($NoMenu -and $OutputCSV) { $results | Export-Csv connections.csv -NoTypeInformation; Write-Host "Exported to connections.csv" }
    elseif ($NoMenu -and $OutputJSON) { $results | ConvertTo-Json }
    else { $results | Format-Table -AutoSize }
}

# Script entry point
if ($NoMenu) {
    if ($NoResolve) { Show-OutboundConnections -NoResolve } else { Show-OutboundConnections }
} else {
    Show-Menu
}

