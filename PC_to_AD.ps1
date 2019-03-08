
# DNS settings

Get-NetIPConfiguration | foreach {

    $if_name = $_ | select -ExpandProperty InterfaceAlias
    $dnsserver = $_ | select -ExpandProperty DNSserver

    $ipv4_dns =  $dnsserver | where {$_.AddressFamily -eq "2"} | select -ExpandProperty Address
    
    if ($ipv4_dns) {
        Write-Host "[*] $if_name IPv4 DNS servers: $ipv4_dns"
    }

}


Get-NetIPConfiguration | foreach {

    $if_name = $_ | select -ExpandProperty InterfaceAlias
    $dnsserver = $_ | select -ExpandProperty DNSserver
    
    $ipv6_dns = $dnsserver | where {$_.AddressFamily -eq "23"} | select -ExpandProperty Address
    if ($ipv6_dns) {
        Write-Host "[*] $if_name IPv6 DNS servers: $ipv6_dns"
    }
}


# Set DNS server:
Set-DnsClientServerAddress -InterfaceAlias "<NAME>" -ServerAddresses ("1","2")


#IPv4 DNS servers:
# Get-NetIPConfiguration | where { $_.InterfaceAlias -eq "PAN_GP" } | select -expandproperty DNSserver | where {$_.AddressFamily -eq "2"} | select InterfaceAlias,AddressFamily,Address 

# IPv6 DNS servers:
# Get-NetIPConfiguration | where { $_.InterfaceAlias -eq "PAN_GP" } | select -expandproperty DNSserver | where {$_.AddressFamily -match "23"} | select InterfaceAlias,AddressFamily,Address 




# PC <-> AD ports: TCP: 389 (LDAP); 135 (RPC); 3268,3269 (LDAP GC); 88 (kerberos); 445 (SMB); 139 (NetBIOS) UDP: 53 (DNS); 88; 138; 389; 464
