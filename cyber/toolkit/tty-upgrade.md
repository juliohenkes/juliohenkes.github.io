---
title: "TTY Upgrade"
---

# TTY Upgrade

Upgrade de shell dumb (sem TTY) para terminal interativo completo. Necessário para usar `sudo`, editores de texto, e comandos que requerem um terminal real. A versão completa restaura o tamanho correto e o tipo de terminal.

```shell
# Rápido
whereis python
/usr/bin/python3.8 -c 'import pty; pty.spawn("/bin/bash")'
```

```shell
# Completo (com resize)
python -c "import pty;pty.spawn('/bin/bash')"
# Ctrl+Z para background
stty -a | head -1 | cut -d';' -f2,3 | tr -d '\;'
export | grep TERM
stty raw -echo
fg
# ENTER ENTER
stty rows 52 columns 236
export TERM=xterm-256color
reset
```
