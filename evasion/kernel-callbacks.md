---
layout: page
title: "Kernel Callbacks: What EDRs Register and Why"
---

# Kernel Callbacks: What EDRs Register and Why

Every bypass technique covered so far operates in user space. Hooks live in NTDLL. AMSI runs in the process. ETW emission is triggered by user-mode code. All of it is reachable without kernel privileges.

The layer beneath is different. The Windows kernel provides notification mechanisms that allow kernel-mode drivers to register callbacks for system-wide events: process creation, thread creation, image loads, handle operations, and filesystem access. These callbacks fire in the kernel, before user space is involved, and cannot be silenced from user space. An EDR that relies on kernel callbacks for its primary detection does not care what state NTDLL is in. The callbacks fire regardless.

Understanding this layer is necessary before BYOVD makes sense. The goal of a vulnerable driver is not arbitrary code execution for its own sake. It is reaching the kernel structures where these callbacks are registered and removing them.

## PsSetCreateProcessNotifyRoutine

Process creation callbacks are registered with `PsSetCreateProcessNotifyRoutine`. The EDR supplies a function pointer. Every time any process on the system is created or exits, the kernel calls that function with the parent PID, the new PID, and a boolean indicating whether the process is being created or deleted.

```c
// EDR's driver registers this at load time
VOID ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE    ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo) {
        // Process is being created
        // CreateInfo->ImageFileName -- path to the executable
        // CreateInfo->CommandLine   -- full command line
        // CreateInfo->ParentProcessId -- parent PID

        // EDR checks: is this a suspicious parent-child relationship?
        // Is the image path in an unexpected location?
        // Does the command line match known attack patterns?

        // Can deny creation entirely:
        // CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}
```

The callback receives the `PS_CREATE_NOTIFY_INFO` structure, which contains the image file name, command line, and parent process ID. The EDR can inspect all three and, critically, deny the process creation by setting `CreateInfo->CreationStatus` to a failure code. Process creation is blocked before the new process ever runs.

This is why `cmd.exe` spawned by `Word.exe` triggers an alert. The parent-child relationship is anomalous. The callback fires at the kernel level before the process exists.

## PsSetLoadImageNotifyRoutine

Image load callbacks fire whenever a PE image is mapped into any process's address space: every DLL load, every `LoadLibrary` call, every module mapped by the loader. The callback receives the image name, the PID of the process, and the image information structure.

```c
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE          ProcessId,
    PIMAGE_INFO     ImageInfo
) {
    // Called for every DLL loaded into every process
    // ImageInfo->ImageBase -- where the image is mapped
    // ImageInfo->ImageSize
    // ImageInfo->SystemModeImage -- TRUE if it's a kernel module

    // EDR checks: is this DLL known? Is its path expected?
    // Is it being loaded into a process it has no business in?
    // Is the image not backed by a file (reflective load)?
}
```

Reflective DLL injection is visible here. A reflectively loaded DLL maps a PE into memory without calling the Windows loader. When the mapping is created through `NtMapViewOfSection` or `VirtualAlloc`, the image load callback may or may not fire depending on how the mapping is created. A directly allocated region with `VirtualAlloc` does not trigger the image load callback because it is not a section-backed mapping. This is one reason reflective injection is preferred: the EDR's image load callback does not see the payload.

But the process of allocating memory, writing a PE header, and executing from that region is itself a behavioral signal logged through other callbacks.

## ObRegisterCallbacks: Handle Stripping

Object callbacks are the most operationally impactful for injection techniques. `ObRegisterCallbacks` allows a driver to register pre- and post-operation callbacks for handle creation and duplication on process and thread objects.

When a process calls `OpenProcess` requesting `PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`, the kernel's object manager fires the pre-operation callback before granting the handle. The EDR's callback examines the requested access mask and the target process. If the target is a protected process (the EDR's own agent, `lsass.exe`, or any process the EDR marks as sensitive), the callback strips dangerous access rights from the requested mask:

```c
OB_PREOP_CALLBACK_STATUS HandlePreCallback(
    PVOID                         RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS target = (PEPROCESS)OperationInformation->Object;

        if (is_protected_process(target)) {
            // Strip VM write and thread creation rights
            OperationInformation->Parameters->CreateHandleInformation
                .DesiredAccess &= ~PROCESS_VM_WRITE;
            OperationInformation->Parameters->CreateHandleInformation
                .DesiredAccess &= ~PROCESS_CREATE_THREAD;
            OperationInformation->Parameters->CreateHandleInformation
                .DesiredAccess &= ~PROCESS_VM_OPERATION;
        }
    }
    return OB_PREOP_SUCCESS;
}
```

The caller receives a handle. But the handle's granted access does not include write or thread creation rights. Any subsequent call to `WriteProcessMemory` or `CreateRemoteThread` using that handle fails with `ERROR_ACCESS_DENIED`. The injection never happens, not because the API call was intercepted, but because the handle was silently downgraded before it was even returned.

This is why direct syscalls do not solve the injection problem against EDRs using handle stripping. The `NtOpenProcess` syscall reaches the kernel. The kernel processes the request. The `ObRegisterCallbacks` callback fires inside the kernel during the handle creation. The returned handle has stripped permissions regardless of how the syscall was issued.

## CmRegisterCallback: Registry Operations

Registry callbacks fire on every registry operation: key opens, value reads, value writes, key deletions. EDRs register these to monitor persistence mechanisms (Run keys, service creation, scheduled tasks), to protect their own registry configuration from tampering, and to detect suspicious registry patterns associated with credential theft (`SAM`, `SECURITY`, `SYSTEM` hive access).

```c
NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,      // REG_NOTIFY_CLASS -- type of operation
    PVOID Argument2       // operation-specific structure
) {
    REG_NOTIFY_CLASS operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (operation == RegNtPreOpenKey ||
        operation == RegNtPreOpenKeyEx) {
        PREG_OPEN_KEY_INFORMATION info =
            (PREG_OPEN_KEY_INFORMATION)Argument2;

        // Is this an attempt to open the SAM hive?
        // Is this an attempt to modify the EDR's own keys?
    }

    return STATUS_SUCCESS;
}
```

The callback can block the operation by returning a failure status. Attempts to read the SAM hive, modify Run keys, or access the EDR's configuration keys are blocked at the kernel level.

## Minifilter Callbacks: Filesystem Operations

Minifilter drivers intercept I/O operations at the filesystem level. They register pre- and post-operation callbacks for specific IRP types: `IRP_MJ_CREATE` (file open/create), `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` (rename, delete). Every file access in the system passes through the minifilter stack.

EDRs use minifilters to scan files on access, detect in-memory-only file access patterns, monitor writes to sensitive directories, and intercept process execution (by intercepting `IRP_MJ_CREATE` on executable files).

```c
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA    Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID                *CompletionContext
) {
    // Data->Iopb->TargetFileObject->FileName -- file being opened
    // Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess

    // Is this an attempt to read a sensitive file?
    // Is this an executable being created in a temp directory?

    // Can deny the operation:
    // Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    // return FLT_PREOP_COMPLETE;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
```

Minifilter callbacks are why writing a payload DLL to disk and loading it is reliably detected even when no NTDLL hook fires. The write and the subsequent open are both intercepted at the filesystem level. The file is scanned on write and again on open.

## Where Callbacks Are Stored

Process creation callbacks are stored in an array `PspCreateProcessNotifyRoutine` in the kernel's non-paged pool. The array holds up to 64 entries (expanded in recent versions). Each entry is an `EX_CALLBACK` structure containing the function pointer and registration context.

Image load callbacks are in `PspLoadImageNotifyRoutine`. Thread callbacks are in `PspCreateThreadNotifyRoutine`. These arrays are at fixed offsets from the kernel image base (NTOSKRNL), discoverable through pattern scanning.

Object callbacks registered via `ObRegisterCallbacks` are stored in the `CallbackList` of the object type structure (`_OBJECT_TYPE`). For process objects, this is accessible through `PsProcessType`.

Registry callbacks are in a list accessible through `CmpCallbackListLock` and the associated list head.

## Enumerating Callbacks from Kernel Space

A kernel driver can walk these structures directly:

```c
// Enumerate process notify callbacks
// Offset of PspCreateProcessNotifyRoutine varies by Windows version
// Found by pattern scanning for the array or by symbol lookup via kernel debugger

extern PVOID PspCreateProcessNotifyRoutine[];  // not exported -- found by offset

void enumerate_process_callbacks(void) {
    for (int i = 0; i < 64; i++) {
        PVOID entry = PspCreateProcessNotifyRoutine[i];
        if (!entry) continue;

        // Each entry is an EX_CALLBACK_ROUTINE_BLOCK pointer
        // with the low bits used as flags -- mask them off
        PVOID callback = (PVOID)((ULONG_PTR)entry & ~0xF);

        // callback now points to the registered function
        // Can zero this entry to remove the callback:
        // PspCreateProcessNotifyRoutine[i] = NULL;
    }
}
```

Zeroing an entry removes the callback. The EDR's driver is still loaded, but its process notification function is never called. From the EDR's perspective, process creation events stop arriving silently.

## PatchGuard

Kernel Patch Protection (PatchGuard) is an integrity verification mechanism running periodically in the kernel. It checks a set of critical kernel structures and BSODs the system if any are modified outside of documented interfaces.

PatchGuard specifically monitors:
- The System Service Descriptor Table (SSDT)
- Interrupt descriptor table (IDT) entries
- Kernel code sections of NTOSKRNL and HAL
- Critical kernel global variables

The callback arrays (`PspCreateProcessNotifyRoutine`, etc.) are not directly protected by PatchGuard in all versions, which is why zeroing them from kernel code is viable. However, modifying the SSDT to redirect syscalls, or patching kernel function bodies, triggers PatchGuard's integrity checks and results in a system crash (`CRITICAL_STRUCTURE_CORRUPTION`, bug check 0x109).

This is the constraint that shapes BYOVD. The goal is not to patch arbitrary kernel structures. The goal is to locate and zero the callback registrations, which PatchGuard does not consistently protect, through kernel code execution obtained via a legitimate but vulnerable driver.

## The Full Detection Stack

Mapping the complete detection surface:

| Layer | Mechanism | Bypassed by |
|---|---|---|
| Disk signature | Scanner on file write | Crypter, obfuscator |
| Heuristic (static) | Import analysis, CFG | Obfuscator, PEB walking |
| User-mode hooks | NTDLL jmp patches | Unhooking, direct syscalls |
| User-mode telemetry | ETW providers | EtwEventWrite patch |
| Script content | AMSI providers | AMSI bypass |
| Process creation | PsSetCreateProcessNotifyRoutine | Kernel access |
| Image load | PsSetLoadImageNotifyRoutine | Kernel access |
| Handle stripping | ObRegisterCallbacks | Kernel access |
| Filesystem | Minifilter IRP callbacks | Kernel access |
| Kernel behavioral | TI ETW provider | Kernel access |

The dividing line is the kernel boundary. Everything above it is addressable from user space. Everything below it requires a kernel driver, which means either a signed legitimate driver with a privilege escalation vulnerability, or a BYOVD scenario where a known-vulnerable driver is brought in explicitly to provide kernel access.
