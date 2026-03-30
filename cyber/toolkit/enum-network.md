---
title: "Network Enumeration"
---

# Network Enumeration

Resolução de hostnames para IPs via PowerView em múltiplos domínios AD. Útil após comprometer um host com acesso ao domínio para mapear toda a infraestrutura interna.

```powershell
# Enumerar todos os hosts do domínio e resolver IPs
Get-NetComputer -Domain final.com | ForEach-Object {
    $hostname = $_.dnshostname
    $ip = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
    [PSCustomObject]@{ DNSHostName = $hostname; IPAddress = $ip.IPAddressToString }
}
```
