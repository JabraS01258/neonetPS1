function Show-NetworkInfo {
    Write-Host "`n=== Network Interfaces ===`n"
    Get-NetIPAddress | Format-Table InterfaceAlias, IPAddress, AddressFamily
}

function Show-ARPTable {
    Write-Host "`n=== Devices Seen (ARP Table) ===`n"
    Get-NetNeighbor | Format-Table ifIndex, IPAddress, LinkLayerAddress, State
}

function Show-OutboundConnections {
    Write-Host "`n=== Outbound Connections ===`n"
    Get-NetTCPConnection -State Established | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            ProcessName   = $proc.ProcessName
        }
    } | Format-Table -AutoSize
}

function Main-Menu {
    while ($true) {
        Write-Host "`n=== NeonNet Recon ==="
        Write-Host "[1] Show My Network Interfaces"
        Write-Host "[2] Show Devices Seen (ARP Table)"
        Write-Host "[3] Show Outbound Connections"
        Write-Host "[4] Exit"
        $choice = Read-Host "Choose an option"

        switch ($choice) {
            "1" { Show-NetworkInfo }
            "2" { Show-ARPTable }
            "3" { Show-OutboundConnections }
            "4" { Write-Host "Goodbye!"; break }
            default { Write-Host "Invalid selection. Please choose 1, 2, 3, or 4." }
        }
    }
}

# Start the script
Main-Menu

