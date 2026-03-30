---
title: "Ticketer"
---

# Ticketer

Conversão de tickets Kerberos entre os formatos `.kirbi` (Windows/Mimikatz) e `.ccache` (Linux/impacket). Necessário para usar tickets obtidos no Windows em ferramentas Linux como `impacket-psexec`, `smbclient`, etc.

```shell
impacket-ticketConverter machine.kirbi machine.ccache
```
