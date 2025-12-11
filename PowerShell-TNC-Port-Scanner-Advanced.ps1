<#
.SYNOPSIS
    Advanced PowerShell Network Port Scanner with CIDR Support

.DESCRIPTION
    PowerShell-TNC-Port-Scanner.ps1 - Enterprise-Grade TCP Port Scanning Utility
    
    This production-ready PowerShell script performs comprehensive TCP port scanning against
    network targets using the Test-NetConnection cmdlet. Designed for network administrators,
    security professionals, and IT auditors to identify open ports across single hosts, 
    multiple IP addresses, or entire network ranges.

.AUTHOR
    Created for enterprise network administration and security operations

.VERSION
    2.0.1 - Production Release

.NOTES
    File Name      : PowerShell-TNC-Port-Scanner.ps1
    Prerequisite   : PowerShell 5.1 or later
    
.LINK
    https://docs.microsoft.com/powershell/module/nettcpip/test-netconnection

#>

function Invoke-NetworkPortScan {
    <#
    .SYNOPSIS
        Performs TCP port scanning against specified network targets.
    
    .DESCRIPTION
        This advanced function scans TCP ports on single hosts, multiple IPs, or entire CIDR ranges.
        Supports flexible port specifications including single ports, ranges, and comma-separated lists.
    
    .PARAMETER TargetHost
        Specifies the target for scanning. Accepts:
        - Hostname (e.g., 'server01.domain.com')
        - Single IP address (e.g., '192.168.1.100')
        - CIDR notation (e.g., '192.168.1.0/24')
    
    .PARAMETER PortSpecification
        Defines which ports to scan. Accepts:
        - Single port: '80'
        - Port range: '1-1024'
        - Comma-separated list: '22,80,443,3389'
    
    .PARAMETER ShowClosedPorts
        Switch to display closed ports in addition to open ports.
    
    .PARAMETER TimeoutMilliseconds
        Connection timeout in milliseconds. Default is 1000ms (1 second).
    
    .EXAMPLE
        Invoke-NetworkPortScan -TargetHost "192.168.1.1" -PortSpecification "1-1024"
        Scans ports 1 through 1024 on a single host.
    
    .EXAMPLE
        Invoke-NetworkPortScan -TargetHost "192.168.1.0/24" -PortSpecification "22,80,443"
        Scans common ports across an entire subnet.
    
    .EXAMPLE
        Invoke-NetworkPortScan -TargetHost "server.local" -PortSpecification "3389" -ShowClosedPorts
        Scans RDP port and shows results even if closed.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0, HelpMessage = "Enter target: hostname, IP, or CIDR (e.g., 192.168.1.0/24)")]
        [ValidateNotNullOrEmpty()]
        [string]$TargetHost,
        
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Enter ports: single (80), range (1-1024), or list (22,80,443)")]
        [ValidateNotNullOrEmpty()]
        [string]$PortSpecification,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowClosedPorts,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 10000)]
        [int]$TimeoutMilliseconds = 1000
    )
    
    begin {
        Write-Verbose "Initializing network port scanner..."
        
        # Collection to store scan results
        [System.Collections.ArrayList]$ScanResultCollection = @()
        [int]$OpenPortCounter = 0
        [int]$ClosedPortCounter = 0
        
        #region Helper Functions
        
        function Expand-CIDRNotation {
            <#
            .SYNOPSIS
                Converts CIDR notation into an array of individual IP addresses.
            #>
            param(
                [Parameter(Mandatory = $true)]
                [string]$CIDRAddress
            )
            
            try {
                # Parse CIDR notation (e.g., 192.168.1.0/24)
                [string]$NetworkAddress, [int]$SubnetMask = $CIDRAddress -split '/'
                
                # Validate subnet mask
                if ($SubnetMask -lt 0 -or $SubnetMask -gt 32) {
                    throw "Invalid subnet mask: $SubnetMask. Must be between 0 and 32."
                }
                
                # Parse IP address into octets
                [System.Net.IPAddress]$IPObject = [System.Net.IPAddress]::Parse($NetworkAddress)
                [byte[]]$IpBytes = $IPObject.GetAddressBytes()
                
                # Convert to 32-bit integer using manual calculation (avoids signed integer issues)
                [uint32]$IpInteger = ([uint32]$IpBytes[0] -shl 24) -bor 
                                     ([uint32]$IpBytes[1] -shl 16) -bor 
                                     ([uint32]$IpBytes[2] -shl 8) -bor 
                                     ([uint32]$IpBytes[3])
                
                # Calculate number of host bits
                [int]$HostBits = 32 - $SubnetMask
                
                # Calculate number of addresses in subnet
                [uint32]$TotalAddresses = [Math]::Pow(2, $HostBits)
                
                # Calculate subnet mask by creating all 1s then shifting
                if ($SubnetMask -eq 0) {
                    [uint32]$SubnetMaskInteger = 0
                } else {
                    # Build mask bit by bit to avoid overflow
                    [uint32]$SubnetMaskInteger = 0
                    for ([int]$i = 0; $i -lt $SubnetMask; $i++) {
                        $SubnetMaskInteger = ($SubnetMaskInteger -shl 1) -bor 1
                    }
                    # Shift to proper position
                    $SubnetMaskInteger = $SubnetMaskInteger -shl $HostBits
                }
                
                # Calculate network address (clear host bits)
                [uint32]$NetworkInteger = $IpInteger -band $SubnetMaskInteger
                
                # Calculate broadcast address (set all host bits)
                [uint32]$BroadcastInteger = $NetworkInteger + ($TotalAddresses - 1)
                
                Write-Verbose "Network: $NetworkInteger, Broadcast: $BroadcastInteger, Total: $TotalAddresses"
                
                # Generate list of usable host IPs
                [System.Collections.ArrayList]$ExpandedIPList = @()
                
                if ($SubnetMask -eq 32) {
                    # Single host (/32) - only the network address itself
                    [void]$ExpandedIPList.Add($NetworkAddress)
                }
                elseif ($SubnetMask -eq 31) {
                    # Point-to-point link (/31) - both addresses usable (RFC 3021)
                    for ([uint32]$CurrentHost = $NetworkInteger; $CurrentHost -le $BroadcastInteger; $CurrentHost++) {
                        [byte]$Octet1 = ($CurrentHost -shr 24) -band 0xFF
                        [byte]$Octet2 = ($CurrentHost -shr 16) -band 0xFF
                        [byte]$Octet3 = ($CurrentHost -shr 8) -band 0xFF
                        [byte]$Octet4 = $CurrentHost -band 0xFF
                        [string]$HostIP = "$Octet1.$Octet2.$Octet3.$Octet4"
                        [void]$ExpandedIPList.Add($HostIP)
                    }
                }
                else {
                    # Standard subnet - exclude network and broadcast addresses
                    [uint32]$FirstUsableHost = $NetworkInteger + 1
                    [uint32]$LastUsableHost = $BroadcastInteger - 1
                    
                    Write-Verbose "Usable range: $FirstUsableHost to $LastUsableHost"
                    
                    for ([uint32]$CurrentHost = $FirstUsableHost; $CurrentHost -le $LastUsableHost; $CurrentHost++) {
                        # Extract octets from 32-bit integer
                        [byte]$Octet1 = ($CurrentHost -shr 24) -band 0xFF
                        [byte]$Octet2 = ($CurrentHost -shr 16) -band 0xFF
                        [byte]$Octet3 = ($CurrentHost -shr 8) -band 0xFF
                        [byte]$Octet4 = $CurrentHost -band 0xFF
                        
                        [string]$HostIP = "$Octet1.$Octet2.$Octet3.$Octet4"
                        [void]$ExpandedIPList.Add($HostIP)
                    }
                }
                
                Write-Verbose "Expanded CIDR $CIDRAddress to $($ExpandedIPList.Count) host(s)"
                return $ExpandedIPList
            }
            catch {
                Write-Error "Failed to parse CIDR notation '$CIDRAddress': $_"
                return @()
            }
        }
        
        function Resolve-TargetHostInput {
            <#
            .SYNOPSIS
                Determines target type and returns array of IP addresses to scan.
            #>
            param(
                [Parameter(Mandatory = $true)]
                [string]$InputTarget
            )
            
            [System.Collections.ArrayList]$ResolvedTargets = @()
            
            # Check if input is CIDR notation
            if ($InputTarget -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
                Write-Verbose "Detected CIDR notation: $InputTarget"
                $ResolvedTargets = Expand-CIDRNotation -CIDRAddress $InputTarget
            }
            # Check if input is IP address
            elseif ($InputTarget -match '^(\d{1,3}\.){3}\d{1,3}$') {
                Write-Verbose "Detected IP address: $InputTarget"
                [void]$ResolvedTargets.Add($InputTarget)
            }
            # Treat as hostname
            else {
                Write-Verbose "Detected hostname: $InputTarget - attempting DNS resolution"
                try {
                    [string]$ResolvedIP = [System.Net.Dns]::GetHostAddresses($InputTarget) | 
                        Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                        Select-Object -First 1 -ExpandProperty IPAddressToString
                    
                    if ($ResolvedIP) {
                        Write-Verbose "Resolved $InputTarget to $ResolvedIP"
                        [void]$ResolvedTargets.Add($ResolvedIP)
                    }
                    else {
                        Write-Error "Unable to resolve hostname: $InputTarget"
                    }
                }
                catch {
                    Write-Error "DNS resolution failed for $InputTarget : $_"
                }
            }
            
            return $ResolvedTargets
        }
        
        function Expand-PortSpecification {
            <#
            .SYNOPSIS
                Parses port specification string into array of port numbers.
            #>
            param(
                [Parameter(Mandatory = $true)]
                [string]$PortInput
            )
            
            [System.Collections.ArrayList]$ExpandedPorts = @()
            
            # Split by comma for multiple specifications
            [string[]]$PortSegments = $PortInput -split ','
            
            foreach ($Segment in $PortSegments) {
                $Segment = $Segment.Trim()
                
                # Check if segment is a range (e.g., "1-1024")
                if ($Segment -match '^(\d+)-(\d+)$') {
                    [int]$RangeStart = [int]$Matches[1]
                    [int]$RangeEnd = [int]$Matches[2]
                    
                    if ($RangeStart -gt $RangeEnd) {
                        Write-Warning "Invalid port range: $Segment (start > end). Skipping."
                        continue
                    }
                    
                    if ($RangeStart -lt 1 -or $RangeEnd -gt 65535) {
                        Write-Warning "Port range $Segment exceeds valid range (1-65535). Skipping."
                        continue
                    }
                    
                    Write-Verbose "Expanding port range: $RangeStart to $RangeEnd"
                    $RangeStart..$RangeEnd | ForEach-Object { [void]$ExpandedPorts.Add($_) }
                }
                # Single port number
                elseif ($Segment -match '^\d+$') {
                    [int]$SinglePort = [int]$Segment
                    
                    if ($SinglePort -lt 1 -or $SinglePort -gt 65535) {
                        Write-Warning "Port $SinglePort is outside valid range (1-65535). Skipping."
                        continue
                    }
                    
                    [void]$ExpandedPorts.Add($SinglePort)
                }
                else {
                    Write-Warning "Invalid port specification: $Segment. Skipping."
                }
            }
            
            # Remove duplicates and sort
            [array]$SortedPorts = $ExpandedPorts | Sort-Object -Unique
            Write-Verbose "Total ports to scan: $($SortedPorts.Count)"
            
            return $SortedPorts
        }
        
        #endregion
        
        # Interactive input if parameters not provided
        if (-not $TargetHost) {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host " Network Port Scanner - Interactive Mode" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
            
            $TargetHost = Read-Host "Enter target (hostname/IP/CIDR)"
        }
        
        if (-not $PortSpecification) {
            Write-Host "`nPort Specification Options:" -ForegroundColor Yellow
            Write-Host "  - Single port: '80'" -ForegroundColor Gray
            Write-Host "  - Port range: '1-1024'" -ForegroundColor Gray
            Write-Host "  - Multiple ports: '22,80,443,3389'" -ForegroundColor Gray
            $PortSpecification = Read-Host "`nEnter port specification"
        }
        
        # Resolve targets and ports
        Write-Host "`n[*] Resolving targets..." -ForegroundColor Cyan
        [array]$TargetIPAddresses = Resolve-TargetHostInput -InputTarget $TargetHost
        
        if ($TargetIPAddresses.Count -eq 0) {
            Write-Error "No valid targets to scan. Exiting."
            return
        }
        
        Write-Host "[*] Parsing port specification..." -ForegroundColor Cyan
        [array]$PortsToScan = Expand-PortSpecification -PortInput $PortSpecification
        
        if ($PortsToScan.Count -eq 0) {
            Write-Error "No valid ports to scan. Exiting."
            return
        }
        
        [int]$TotalScansRequired = $TargetIPAddresses.Count * $PortsToScan.Count
        Write-Host "[*] Scan Configuration:" -ForegroundColor Green
        Write-Host "    Targets: $($TargetIPAddresses.Count)" -ForegroundColor White
        Write-Host "    Ports: $($PortsToScan.Count)" -ForegroundColor White
        Write-Host "    Total Probes: $TotalScansRequired" -ForegroundColor White
        Write-Host ""
    }
    
    process {
        Write-Host "[*] Initiating port scan...`n" -ForegroundColor Cyan
        
        # Pipeline-based scanning approach (different from original foreach loop)
        $TargetIPAddresses | ForEach-Object {
            [string]$CurrentTarget = $_
            
            $PortsToScan | ForEach-Object {
                [int]$CurrentPort = $_
                
                Write-Verbose "Scanning ${CurrentTarget}:${CurrentPort}"
                
                try {
                    # Perform TCP connection test
                    $ConnectionTestResult = Test-NetConnection -ComputerName $CurrentTarget `
                                                               -Port $CurrentPort `
                                                               -InformationLevel Quiet `
                                                               -WarningAction SilentlyContinue `
                                                               -ErrorAction SilentlyContinue
                    
                    # Create result object
                    [PSCustomObject]$ScanResult = [PSCustomObject]@{
                        TargetHost   = $CurrentTarget
                        Port         = $CurrentPort
                        Status       = if ($ConnectionTestResult) { "OPEN" } else { "CLOSED" }
                        Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    
                    [void]$ScanResultCollection.Add($ScanResult)
                    
                    # Display results based on status
                    if ($ConnectionTestResult) {
                        $OpenPortCounter++
                        Write-Host "[+] OPEN: ${CurrentTarget}:${CurrentPort}" -ForegroundColor Green
                    }
                    else {
                        $ClosedPortCounter++
                        if ($ShowClosedPorts) {
                            Write-Host "[-] CLOSED: ${CurrentTarget}:${CurrentPort}" -ForegroundColor Red
                        }
                    }
                }
                catch {
                    Write-Warning "Error scanning ${CurrentTarget}:${CurrentPort} - $_"
                }
            }
        }
    }
    
    end {
        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host " Scan Summary" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "Total Ports Scanned: $($OpenPortCounter + $ClosedPortCounter)" -ForegroundColor White
        Write-Host "Open Ports Found: $OpenPortCounter" -ForegroundColor Green
        Write-Host "Closed Ports: $ClosedPortCounter" -ForegroundColor Red
        Write-Host "============================================`n" -ForegroundColor Cyan
        
        # Output detailed results for open ports
        if ($OpenPortCounter -gt 0) {
            Write-Host "Open Ports Detail:" -ForegroundColor Yellow
            $ScanResultCollection | Where-Object { $_.Status -eq "OPEN" } | ForEach-Object {
                Write-Host "  ✓ $($_.TargetHost):$($_.Port)" -ForegroundColor Green
            }
        }
        
        # Return results object for pipeline usage
        Write-Output $ScanResultCollection
        
        Write-Verbose "Port scan operation completed successfully"
    }
}

# Example usage - uncomment to run:
# Invoke-NetworkPortScan -TargetHost 192.168.1.1 -PortSpecification 1-1024
# Invoke-NetworkPortScan -TargetHost 192.168.1.0/24 -PortSpecification 22,80,443
# Invoke-NetworkPortScan
