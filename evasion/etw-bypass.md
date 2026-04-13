---
layout: page
title: "ETW Bypass: Blinding the Telemetry Layer"
---

# ETW Bypass: Blinding the Telemetry Layer

Direct syscalls and unhooking eliminate user-mode API interception. What remains is telemetry: a parallel data stream flowing from providers throughout the OS to consumers that EDRs subscribe to. This stream does not depend on hooks. It operates through Event Tracing for Windows (ETW), a kernel-level infrastructure that logs system activity independently of whether any NTDLL function was hooked or not.

An EDR that loses its hooks still receives ETW events. Process creation, image loads, memory allocation patterns, and PowerShell script content all flow through ETW providers that the EDR monitors. Bypassing hooks without addressing ETW leaves the most informative telemetry channel intact.

## ETW Architecture

ETW has four components. Providers instrument code and emit events. Sessions collect events from one or more providers. Controllers start and stop sessions. Consumers read the event stream, either in real time or from a log file.

Providers register with the ETW subsystem and emit events through `EtwEventWrite` in NTDLL. A provider can exist in user space (any process that calls `EventRegister`) or in kernel space (drivers that call `EtwRegister`). The ETW subsystem routes events from providers to any sessions that have enabled that provider.

EDRs register as consumers of specific providers. The most important is `Microsoft-Windows-Threat-Intelligence`, a kernel-mode provider that emits events for operations that security products care about: process injection patterns, handle manipulation, memory protection changes. This provider runs entirely in the kernel and is not accessible from user space.

Other providers that feed EDR telemetry:

- `Microsoft-Windows-PowerShell` -- emits script block content before execution
- `Microsoft-Windows-DotNETRuntime` -- CLR method invocations and JIT activity
- `Microsoft-Windows-Kernel-Process` -- process and thread creation events
- `Microsoft-Windows-Kernel-File` -- filesystem operations

## Patching EtwEventWrite

Every user-mode ETW event goes through `EtwEventWrite` in NTDLL. Patching it to return immediately stops all user-mode ETW emission from the process. No provider running in user space emits events. The patch is two bytes: `xor eax, eax` (`33 C0`) followed by `ret` (`C3`), which returns `ERROR_SUCCESS` without doing anything.

```c
void patch_etw_write(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    LPVOID  etw   = GetProcAddress(ntdll, "EtwEventWrite");

    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret

    DWORD old;
    VirtualProtect(etw, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(etw, patch, sizeof(patch));
    VirtualProtect(etw, sizeof(patch), old, &old);
}
```

After this patch, any call to `EtwEventWrite` from any provider in the process returns immediately. PowerShell script block logging stops. CLR method events stop. Any user-mode security product relying on ETW from within the process sees nothing.

The limitation is scope: this patch affects only the current process. Other processes continue emitting ETW events normally. And kernel-mode providers, including `Microsoft-Windows-Threat-Intelligence`, are not affected because they call `EtwWrite` in the kernel, not `EtwEventWrite` in NTDLL.

## Provider-Level Disabling via Registration Structure

A more surgical approach targets the ETW provider registration structure directly. When a provider calls `EventRegister`, the ETW subsystem returns a registration handle backed by an `_ETW_GUID_ENTRY` structure. This structure contains a field that tracks whether the provider is enabled for any session. If that field reads zero, the provider skips event emission internally before `EtwEventWrite` is ever called.

Finding the registration handle for a specific provider requires walking the provider list. Each registered provider links into a global list maintained by NTDLL. The list head is accessible through an undocumented NTDLL global symbol, or by scanning the NTDLL data section for the known structure layout.

For the PowerShell ETW provider specifically, the registration handle is stored in a known CLR or PowerShell internal. Locating and zeroing the `IsEnabled` field in the backing structure silences that provider without touching `EtwEventWrite` at all:

```c
// PowerShell stores its ETW provider handle in a known exported symbol
// (varies by version; this is a conceptual sketch)

typedef struct _ETW_GUID_ENTRY {
    // ... internal fields
    ULONG IsEnabled;          // non-zero if any session has enabled this provider
    // ... more fields
} ETW_GUID_ENTRY;

void disable_powershell_etw_provider(REGHANDLE reg_handle) {
    // The REGHANDLE is a pointer to the internal ETW_GUID_ENTRY
    ETW_GUID_ENTRY *entry = (ETW_GUID_ENTRY *)reg_handle;

    DWORD old;
    VirtualProtect(entry, sizeof(*entry), PAGE_READWRITE, &old);
    entry->IsEnabled = 0;
    VirtualProtect(entry, sizeof(*entry), old, &old);
}
```

The provider still calls `EtwEventWrite`, but internally checks `IsEnabled` first. When `IsEnabled` is zero, the call returns without emitting anything. No patch to `EtwEventWrite` itself, and the modification is invisible to tools that check the `EtwEventWrite` bytes.

## Targeting the .NET Runtime

When PowerShell executes, the CLR emits ETW events for every method JIT-compiled and every script block executed. These events flow through `Microsoft-Windows-DotNETRuntime`. EDRs use them to inspect PowerShell content after AMSI has been bypassed or before it runs.

The CLR's ETW emission goes through `EtwEventWrite` like any other user-mode provider. Patching `EtwEventWrite` before the CLR loads, or before a specific script block executes, kills this telemetry entirely. Timing matters: if the CLR has already emitted the ScriptBlock event before the patch is in place, the content is already in the ETW stream.

For in-process scenarios (injecting into a PowerShell process), the patch should be applied as early as possible, before the first user-supplied script block is JIT-compiled.

## The NtTraceEvent Alternative

Some implementations bypass `EtwEventWrite` entirely and call `NtTraceEvent` directly to test whether the kernel still routes events when the user-mode wrapper is patched. They do. `EtwEventWrite` is a convenience wrapper. Patching it stops events from providers that use the standard API. Providers that call `NtTraceEvent` directly are unaffected.

In practice, most EDR-relevant providers use `EtwEventWrite`. But knowing the bypass is at the wrapper level, not the syscall level, matters for completeness. Patching `NtTraceEvent` (or its NTDLL entry point) stops all user-mode ETW at the syscall boundary:

```c
void patch_etw_at_syscall_level(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    // Patch both the wrapper and the underlying syscall stub
    const char *targets[] = { "EtwEventWrite", "NtTraceEvent", NULL };

    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret

    for (int i = 0; targets[i]; i++) {
        LPVOID func = GetProcAddress(ntdll, targets[i]);
        DWORD  old;
        VirtualProtect(func, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
        memcpy(func, patch, sizeof(patch));
        VirtualProtect(func, sizeof(patch), old, &old);
    }
}
```

## Detecting the Patch

EDRs that monitor their own telemetry integrity check the `EtwEventWrite` bytes periodically. If the first bytes match a known patch pattern (`33 C0 C3`, `C3` alone, or a jump to an unexpected address), the process is flagged.

The counter is to use a hook-style trampoline instead of a hard `ret`. Redirect `EtwEventWrite` to a stub that filters events by provider GUID, allowing benign events through and dropping security-relevant ones. From an integrity check's perspective, `EtwEventWrite` is modified but not silenced entirely. The bytes differ from the original, but so does any legitimate hook. Without checking the destination of the redirect, the integrity check cannot distinguish between your filter and a legitimate hook.

## The Kernel Boundary

The `Microsoft-Windows-Threat-Intelligence` provider is the most valuable source for EDRs. It emits events directly from kernel callbacks when operations like `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` execute with characteristics matching injection patterns. These events are emitted in the kernel by the callback itself, not by any user-mode code.

Patching `EtwEventWrite` does not touch kernel-mode ETW emission. The TI provider events continue to flow regardless of what user-mode patches are applied. Stopping kernel ETW requires either a kernel-mode exploit, a vulnerable driver, or operating in a way that does not trigger the specific callback conditions the TI provider monitors.

The practical boundary: patching `EtwEventWrite` silences PowerShell logging, CLR method tracing, and any user-mode security telemetry. Kernel callbacks and the TI provider remain active. Against a well-configured EDR that relies heavily on TI provider data, user-mode ETW bypass removes some visibility but not the deepest layer.

## Combining with Unhooking and Direct Syscalls

Each technique covers a different detection channel:

- **Unhooking** removes user-mode API interception from NTDLL hooks
- **Direct syscalls** eliminates NTDLL as an interception point entirely
- **ETW bypass** silences user-mode telemetry providers

Applied together before any payload activity, they eliminate the three user-mode detection mechanisms that EDRs depend on. What remains is kernel-mode: callbacks, the TI provider, and minifilter drivers. Addressing those requires kernel access.
