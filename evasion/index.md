---
layout: page
title: evasion
---

## evasion

<p class="section-desc">AV and EDR evasion: detection mechanisms, bypass techniques, and in-memory execution.</p>

<span class="section-label">fundamentals</span>

<div class="wu-list">
  <a href="{{ '/evasion/av-evasion-basics/' | relative_url }}">The Minimum You Need to Know About Antivirus Evasion</a>
  <a href="{{ '/evasion/crypters/' | relative_url }}">Crypters: Hiding Payloads on Disk</a>
  <a href="{{ '/evasion/obfuscators/' | relative_url }}">Obfuscators: Making Malicious Code Unrecognizable</a>
</div>

<span class="section-label">in-memory execution</span>

<div class="wu-list">
  <a href="{{ '/evasion/process-injection/' | relative_url }}">Process Injection: Executing Inside Another Process</a>
  <a href="{{ '/evasion/process-hollowing/' | relative_url }}">Process Hollowing: Replacing a Legitimate Process</a>
  <a href="{{ '/evasion/reflective-dll-injection/' | relative_url }}">Reflective DLL Injection: Loading Without the Loader</a>
</div>

<span class="section-label">hooks and telemetry</span>

<div class="wu-list">
  <a href="{{ '/evasion/unhooking/' | relative_url }}">Unhooking: Restoring the Windows API</a>
  <a href="{{ '/evasion/direct-syscalls/' | relative_url }}">Direct Syscalls: Bypassing User-Mode Hooks Entirely</a>
  <a href="{{ '/evasion/etw-bypass/' | relative_url }}">ETW Bypass: Blinding the Telemetry Layer</a>
</div>

<span class="section-label">amsi</span>

<div class="wu-list">
  <a href="{{ '/evasion/amsi-internals/' | relative_url }}">AMSI Internals: How Script Content is Inspected</a>
  <a href="{{ '/evasion/amsi-bypass/' | relative_url }}">AMSI Bypass: Patching the Inspection Pipeline</a>
  <a href="{{ '/evasion/amsi-drx-bypass/' | relative_url }}">AMSI Bypass via Hardware Breakpoints: Working Implementation</a>
</div>

<span class="section-label">kernel</span>

<div class="wu-list">
  <a href="{{ '/evasion/kernel-callbacks/' | relative_url }}">Kernel Callbacks: What EDRs Register and Why</a>
  <a href="{{ '/evasion/byovd/' | relative_url }}">BYOVD: Exploiting Signed Drivers to Reach the Kernel</a>
  <a href="{{ '/evasion/ppl-bypass/' | relative_url }}">PPL Bypass: Attacking Protected Processes</a>
</div>

<span class="section-label">bonus</span>

<div class="wu-list">
  <a href="{{ '/evasion/full-chain/' | relative_url }}">Full Chain: Bypassing a Modern EDR End to End</a>
</div>
