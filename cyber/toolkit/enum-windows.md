---
title: "Windows File Enum"
---

# Windows File Enum

Enumeração de arquivos sensíveis e histórico de comandos PowerShell em hosts Windows. Busca por bases KeePass, arquivos de texto e e-mails, além do histórico PSReadLine que frequentemente contém credenciais.

```powershell
# Buscar arquivos sensíveis em C:\Users
Get-ChildItem -Path C:\Users -Include *.kdbx,*.txt,*.eml -File -Recurse -ErrorAction SilentlyContinue

# Listar estrutura de diretórios
tree /f

# Localizar e ler histórico PSReadLine
(Get-PSReadlineOption).HistorySavePath
Get-History
```
