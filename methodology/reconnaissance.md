---
title: "Reconnaissance"
---

# Reconnaissance

Reconnaissance is the phase that determines the quality of everything that follows. The more accurate the attack surface map, the fewer wasted hours chasing dead ends. This covers both passive intelligence gathering and active scanning as I apply it in practice.

## Passive Reconnaissance

### Company and Infrastructure Intelligence

Before touching a single packet, public information gives a solid baseline. Job postings are underrated — a company advertising for "Senior AWS Engineer" or "FortiGate Administrator" reveals the technology stack without any active interaction.

```
# Google dorks
site:target.com filetype:pdf
site:target.com ext:xlsx OR ext:docx OR ext:csv
site:target.com inurl:admin OR inurl:login OR inurl:portal
"@target.com" site:linkedin.com
"target.com" site:pastebin.com
```

WHOIS and DNS records establish the IP ranges and infrastructure owners:

```bash
whois target.com
whois <IP>

# Reverse DNS
host <IP>
dig -x <IP>

# Zone transfer attempt (rarely works, but worth trying)
dig axfr @ns1.target.com target.com

# Subdomain brute force via DNS
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# DNSrecon
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Certificate Transparency

SSL certificates are logged publicly and expose subdomains that would otherwise be invisible:

```bash
# crt.sh via curl
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# certspotter
curl -s "https://certspotter.com/api/v0/certs?domain=target.com" | jq '.[].dns_names[]'
```

### TheHarvester

Email addresses, hostnames, and employee names from public sources:

```bash
theHarvester -d target.com -b all -l 500
theHarvester -d target.com -b google,bing,linkedin,shodan
```

### Shodan

Exposed services indexed by Shodan reveal attack surface before any active scanning:

```bash
# CLI
shodan search "hostname:target.com"
shodan search "org:\"Target Inc\""
shodan host <IP>

# Filters
shodan search "port:3389 org:\"Target Inc\""
shodan search "http.title:\"Employee Portal\" org:\"Target Inc\""
```

## Active Scanning

### Standard Nmap

My baseline scan for every target — full port sweep with service version detection and default scripts:

```bash
sudo nmap -sCV -p- --min-rate=10000 -Pn <IP>
```

Flag breakdown:
- `-sCV` — combines `-sC` (default scripts) and `-sV` (version detection)
- `-p-` — all 65535 ports, not just top 1000
- `--min-rate=10000` — aggressive timing, acceptable noise for lab/CTF
- `-Pn` — skip host discovery, treat all hosts as up

### Stealth Scan

When ICMP is blocked or a quieter approach is needed:

```bash
sudo nmap -v -sSV -O -p- --min-rate=10000 -Pn <IP>
```

- `-sS` — TCP SYN scan (half-open, doesn't complete the handshake)
- `-O` — OS detection
- `-v` — verbose, shows open ports as they're discovered

### Targeted Service Scripts

After initial discovery, deeper enumeration of specific services:

```bash
# SSH — check which auth methods are enabled (publickey, password, keyboard-interactive)
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 <IP>

# SMB — full enumeration suite
nmap --script smb-enum* -p 445 <IP>
nmap --script smb-vuln* -p 445 <IP>

# Redis — often unauthenticated
nmap --script redis-info -sV -p 6379 <IP>

# HTTP enumeration
nmap --script http-enum -p 80,443,8080,8443 <IP>
nmap --script http-methods -p 80,443 <IP>

# SNMP
nmap -sU --script snmp-info -p 161 <IP>
nmap -sU --script snmp-brute -p 161 <IP>

# FTP
nmap --script ftp-anon,ftp-bounce -p 21 <IP>

# SMTP
nmap --script smtp-enum-users,smtp-commands -p 25 <IP>
```

### Output Formats

Save all scan results for later reference:

```bash
# All formats at once
sudo nmap -sCV -p- --min-rate=10000 -Pn <IP> -oA scan_<IP>

# Grepable output for quick parsing
grep -E "^[0-9]+/tcp" scan_<IP>.gnmap | awk '{print $1}'
```

## Web Application Fingerprinting

### WhatWeb and Technology Detection

```bash
whatweb http://target.com
whatweb -v http://target.com

# Wappalyzer CLI
node_modules/.bin/wappalyzer http://target.com
```

### Directory and File Enumeration

```bash
# Gobuster — my standard wordlist
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html,bak,old -t 40

# Feroxbuster — recursive
feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html -t 40 --depth 3

# Nikto — vulnerability scanner
nikto -h http://<IP>
```

### Virtual Host Enumeration

Applications often respond differently based on the `Host` header:

```bash
gobuster vhost -u http://<IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
ffuf -u http://<IP> -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fc 200 -fs <default_size>
```

## Network Range Discovery

When given a network block rather than a single IP:

```bash
# Ping sweep
nmap -sn 192.168.1.0/24
nmap -sn 10.0.0.0/8 --min-rate=5000

# ARP scan (layer 2, more reliable on local network)
arp-scan -l
arp-scan 192.168.1.0/24

# netdiscover
netdiscover -r 192.168.1.0/24
```

## Service-Specific Deep Dives

### SMB

```bash
# Anonymous enumeration
smbclient -L //<IP> -N
smbclient //<IP>/share -N

# CrackMapExec
crackmapexec smb <IP>
crackmapexec smb <IP> -u '' -p '' --shares
crackmapexec smb <IP> -u 'guest' -p '' --shares

# Enum4linux
enum4linux -a <IP>

# SMBmap
smbmap -H <IP>
smbmap -H <IP> -u '' -p ''
```

### LDAP / Active Directory

```bash
# Anonymous LDAP query
ldapsearch -H ldap://<IP> -x -s base namingcontexts
ldapsearch -H ldap://<IP> -x -b "DC=domain,DC=local" "(objectClass=*)" | head -100

# Windapsearch
python3 windapsearch.py --dc-ip <IP> -U  # enumerate users
python3 windapsearch.py --dc-ip <IP> -G  # enumerate groups
```

### SNMP

```bash
# Community string brute force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>

# Walk with community string
snmpwalk -v2c -c public <IP>
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2  # running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.6.13.1.3     # open TCP ports
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.77.1.2.25   # user accounts (Windows)
```

## Recon Notes Methodology

Every engagement gets a notes file structured like:

```
Target: <IP>
Hostname: <hostname>
OS: <OS>
Open Ports: <list>

Services:
  80/tcp   - Apache 2.4.41
  443/tcp  - Apache 2.4.41 (SSL)
  22/tcp   - OpenSSH 7.4

Web:
  http://<IP>/         - Default page
  http://<IP>/admin/   - Login panel → credentials found: admin:admin
  http://<IP>/backup/  - Directory listing

Credentials:
  admin:admin (web admin panel)

Vulnerabilities:
  - Apache 2.4.41 — check for CVE-XXXX

Next steps:
  - Try SQLi on login form
  - Enumerate /backup/ contents
```

This structure keeps the attack chain readable and prevents losing track of findings during longer engagements.
