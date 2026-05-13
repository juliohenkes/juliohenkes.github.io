---
layout: page
title: evasion
description: "AV/EDR evasion — detection internals, in-memory execution, hooks, AMSI, and kernel telemetry bypass."
---

<header class="section-hero">
  <div class="section-kicker">dossier · 01</div>
  <h1 class="section-title"><em>Evasion</em></h1>
  <p class="section-lede">
    AV and EDR evasion. Detection mechanisms, bypass techniques, and in-memory execution
    — from AMSI patching to BYOVD and PPL.
  </p>
</header>

<section class="section-group">
  <h2 class="section-group-label" data-num="01">fundamentals</h2>
  <div class="entry-list">
    <a href="{{ '/evasion/av-evasion-basics/' | relative_url }}"><span class="idx">01</span><span>The Minimum You Need to Know About Antivirus Evasion</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/crypters/' | relative_url }}"><span class="idx">02</span><span>Crypters: Hiding Payloads on Disk</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/obfuscators/' | relative_url }}"><span class="idx">03</span><span>Obfuscators: Making Malicious Code Unrecognizable</span><span class="arrow">→</span></a>
  </div>
</section>

<section class="section-group">
  <h2 class="section-group-label" data-num="02">in-memory execution</h2>
  <div class="entry-list">
    <a href="{{ '/evasion/process-injection/' | relative_url }}"><span class="idx">04</span><span>Process Injection: Executing Inside Another Process</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/process-hollowing/' | relative_url }}"><span class="idx">05</span><span>Process Hollowing: Replacing a Legitimate Process</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/reflective-dll-injection/' | relative_url }}"><span class="idx">06</span><span>Reflective DLL Injection: Loading Without the Loader</span><span class="arrow">→</span></a>
  </div>
</section>

<section class="section-group">
  <h2 class="section-group-label" data-num="03">hooks &amp; telemetry</h2>
  <div class="entry-list">
    <a href="{{ '/evasion/unhooking/' | relative_url }}"><span class="idx">07</span><span>Unhooking: Restoring the Windows API</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/direct-syscalls/' | relative_url }}"><span class="idx">08</span><span>Direct Syscalls: Bypassing User-Mode Hooks Entirely</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/etw-bypass/' | relative_url }}"><span class="idx">09</span><span>ETW Bypass: Blinding the Telemetry Layer</span><span class="arrow">→</span></a>
  </div>
</section>

<section class="section-group">
  <h2 class="section-group-label" data-num="04">amsi</h2>
  <div class="entry-list">
    <a href="{{ '/evasion/amsi-internals/' | relative_url }}"><span class="idx">10</span><span>AMSI Internals: How Script Content is Inspected</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/amsi-bypass/' | relative_url }}"><span class="idx">11</span><span>AMSI Bypass: Patching the Inspection Pipeline</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/amsi-drx-bypass/' | relative_url }}"><span class="idx">12</span><span>AMSI Bypass via Hardware Breakpoints</span><span class="arrow">→</span></a>
  </div>
</section>

<section class="section-group">
  <h2 class="section-group-label" data-num="05">kernel</h2>
  <div class="entry-list">
    <a href="{{ '/evasion/kernel-callbacks/' | relative_url }}"><span class="idx">13</span><span>Kernel Callbacks: What EDRs Register and Why</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/byovd/' | relative_url }}"><span class="idx">14</span><span>BYOVD: Exploiting Signed Drivers to Reach the Kernel</span><span class="arrow">→</span></a>
    <a href="{{ '/evasion/ppl-bypass/' | relative_url }}"><span class="idx">15</span><span>PPL Bypass: Attacking Protected Processes</span><span class="arrow">→</span></a>
  </div>
</section>

<section class="section-group">
  <h2 class="section-group-label" data-num="06">bonus</h2>
  <div class="entry-list">
    <a href="{{ '/evasion/full-chain/' | relative_url }}"><span class="idx">16</span><span>Full Chain: Bypassing a Modern EDR End to End</span><span class="arrow">→</span></a>
  </div>
</section>
