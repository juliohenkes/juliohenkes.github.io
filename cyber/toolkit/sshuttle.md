---
title: "sshuttle"
---

# sshuttle

Pivoting via sshuttle sobre túnel SSH reverso. O host comprometido (pivô) cria um túnel SSH reverso para o Kali, que usa sshuttle para rotear todo o tráfego destinado à rede interna como se fosse uma VPN.

```shell
# No pivô — criar túnel SSH reverso para o Kali (porta 3000)
ssh <user_pivo2>@<ip_pivo1> -p 3000

# No Kali — roteamento transparente via sshuttle
sshuttle -r <user_pivo2>@<ip_vps_pivo1>:3000 <rede_alvo3> --disable-ipv6
```
