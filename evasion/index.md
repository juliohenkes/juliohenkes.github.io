---
layout: page
title: evasion
---

## evasion

<p class="section-desc">AV and EDR evasion: detection mechanisms, bypass techniques, and in-memory execution.</p>

<span class="section-label">fundamentos</span>

<div class="wu-list">
  <a href="{{ '/evasion/av-evasion-basics/' | relative_url }}">The Minimum You Need to Know About Antivirus Evasion</a>
  <a href="{{ '/evasion/crypters/' | relative_url }}">Crypters: Hiding Payloads on Disk</a>
  <a href="{{ '/evasion/obfuscators/' | relative_url }}">Obfuscators: Making Malicious Code Unrecognizable</a>
</div>

<span class="section-label">execução em memória</span>

<div class="wu-list">
  <a href="{{ '/evasion/process-injection/' | relative_url }}">Process Injection: Executing Inside Another Process</a>
  <a href="{{ '/evasion/process-hollowing/' | relative_url }}">Process Hollowing: Replacing a Legitimate Process</a>
  <a href="{{ '/evasion/reflective-dll-injection/' | relative_url }}">Reflective DLL Injection: Loading Without the Loader</a>
</div>

<span class="section-label">evasão de hooks e telemetria</span>

<div class="wu-list">
  <a href="{{ '/evasion/unhooking/' | relative_url }}">Unhooking: Restoring the Windows API</a>
  <a href="{{ '/evasion/direct-syscalls/' | relative_url }}">Direct Syscalls: Bypassing User-Mode Hooks Entirely</a>
  <a href="{{ '/evasion/etw-bypass/' | relative_url }}">ETW Bypass: Blinding the Telemetry Layer</a>
</div>

<span class="section-label">amsi</span>

<div class="wu-list">
  <a href="{{ '/evasion/amsi-internals/' | relative_url }}">AMSI Internals: How Script Content is Inspected</a>
  <span class="empty">AMSI Bypass: Patching the Inspection Pipeline</span>
</div>

<span class="section-label">kernel</span>

<div class="wu-list">
  <span class="empty">Kernel Callbacks: What EDRs Register and Why</span>
  <span class="empty">BYOVD: Exploiting Signed Drivers to Reach the Kernel</span>
  <span class="empty">PPL Bypass: Attacking Protected Processes</span>
</div>

<span class="section-label">execução sem arquivo</span>

<div class="wu-list">
  <span class="empty">Fileless Execution: Living Entirely in Memory</span>
  <span class="empty">COM Hijacking: Persistence Without Writing Executables</span>
</div>
