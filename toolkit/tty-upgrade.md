---
title: "TTY Upgrade"
---

# TTY Upgrade

Upgrade from a dumb shell (no TTY) to a full interactive terminal. Required for using `sudo`, text editors, and commands that need a real terminal. The full version also restores the correct terminal size and type.

```shell
# Quick
whereis python
/usr/bin/python3.8 -c 'import pty; pty.spawn("/bin/bash")'
```

```shell
# Full (with resize)
python -c "import pty;pty.spawn('/bin/bash')"
# Ctrl+Z to background
stty -a | head -1 | cut -d';' -f2,3 | tr -d '\;'
export | grep TERM
stty raw -echo
fg
# ENTER ENTER
stty rows 52 columns 236
export TERM=xterm-256color
reset
```
