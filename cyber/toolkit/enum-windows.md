---
title: "Windows File Enum"
---

# Windows File Enum

Enumerates sensitive files and PowerShell command history on Windows hosts. Searches for KeePass databases, text files, and emails, as well as PSReadLine history which often contains credentials.

```powershell
# Search for sensitive files under C:\Users
Get-ChildItem -Path C:\Users -Include *.kdbx,*.txt,*.eml -File -Recurse -ErrorAction SilentlyContinue

# List directory tree
tree /f

# Locate and read PSReadLine history
(Get-PSReadlineOption).HistorySavePath
Get-History
```
