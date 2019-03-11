
Write-Host "[!] Please enter Domain Controller IP address to test: "
#$dc = Read-Host
$dc = 127.0.0.1

$ports = 88,135,389, 445
# PC <-> AD ports: TCP: 389 (LDAP); 135 (RPC); 3268,3269 (LDAP GC); 88 (kerberos); 445 (SMB); 139 (NetBIOS) UDP: 53 (DNS); 88; 138; 389; 464



Test-NetConnection -ComputerName  -Port 53 -InformationLevel Quiet


# ====================================

# DNS settings

Write-Host "`n[*] IPv4 DNS settings.."

Get-NetIPConfiguration | foreach {

    $if_name = $_ | select -ExpandProperty InterfaceAlias
    $dnsserver = $_ | select -ExpandProperty DNSserver

    $ipv4_dns =  $dnsserver | where {$_.AddressFamily -eq "2"} | select -ExpandProperty Address
    
    if ($ipv4_dns) {
        Write-Host "`t[*] $if_name IPv4 DNS servers: $ipv4_dns"
    }

}

Write-Host "`n[*] IPv6 DNS settings.."

Get-NetIPConfiguration | foreach {

    $if_name = $_ | select -ExpandProperty InterfaceAlias
    $dnsserver = $_ | select -ExpandProperty DNSserver
    
    $ipv6_dns = $dnsserver | where {$_.AddressFamily -eq "23"} | select -ExpandProperty Address
    if ($ipv6_dns) {
        Write-Host "`t[*] $if_name IPv6 DNS servers: $ipv6_dns"
    }
}

<#
Write-Host "`n[?] Do you want to change settings for any of interfaces? [y/N] " -NoNewline
$configure_dns = Read-Host

if ($configure_dns -eq 'y') {
    Write-Host "`t[*] Enter Interface name settings to apply: " -NoNewline
    $if_conf = Read-Host
    Write-Host "`t[*] Enter DNS server[s] (separate by space if multiple): " -NoNewline
    $new_dns = Read-Host

    Write-Host

    Write-Host $if_conf, $new_dns

} elseif ($configure_dns -eq 'n' -or $configure_dns.Length -eq 0) {} else {
    Write-Host "[-] Didn't understand your input. Continuing..." -ForegroundColor Red
}
#>

# Set DNS server:
#Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("8.8.8.8","::1")


#IPv4 DNS servers:
# Get-NetIPConfiguration | where { $_.InterfaceAlias -eq "PAN_GP" } | select -expandproperty DNSserver | where {$_.AddressFamily -eq "2"} | select InterfaceAlias,AddressFamily,Address 

# IPv6 DNS servers:
# Get-NetIPConfiguration | where { $_.InterfaceAlias -eq "PAN_GP" } | select -expandproperty DNSserver | where {$_.AddressFamily -match "23"} | select InterfaceAlias,AddressFamily,Address 

