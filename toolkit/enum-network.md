---
title: "Network Enumeration"
---

# Network Enumeration

Resolves hostnames to IPs via PowerView across multiple AD domains. Useful after compromising a domain-joined host to map the full internal infrastructure.

```powershell
# Enumerate all domain computers and resolve their IPs
Get-NetComputer -Domain final.com | ForEach-Object {
    $hostname = $_.dnshostname
    $ip = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
    [PSCustomObject]@{ DNSHostName = $hostname; IPAddress = $ip.IPAddressToString }
}
```
