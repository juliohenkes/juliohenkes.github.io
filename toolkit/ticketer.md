---
title: "Ticketer"
---

# Ticketer

Converts Kerberos tickets between `.kirbi` (Windows/Mimikatz) and `.ccache` (Linux/impacket) formats. Required to use tickets obtained on Windows with Linux tools such as `impacket-psexec`, `smbclient`, etc.

```shell
impacket-ticketConverter machine.kirbi machine.ccache
```
