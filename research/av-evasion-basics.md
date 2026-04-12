---
layout: page
title: "The Minimum You Need to Know About Antivirus Evasion"
---

# The Minimum You Need to Know About Antivirus Evasion

Antivirus is not your biggest problem anymore. Most mature enterprise environments today run EDR: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint. But understanding how AV works is the prerequisite for everything that comes after. EDR detection logic is built on the same foundations. And you will encounter traditional AV in real engagements more often than you expect.

Start here.

## How AV Detects Threats

No serious AV product relies on a single method. Detection is layered. Each layer compensates for the blind spots of the one before it. Understanding what each layer sees, and what it cannot see, is the foundation of evasion.

### Signature-Based Detection

The engine maintains a database of known malware signatures. A signature can be a file hash, a specific byte sequence at a fixed offset, or a pattern that uniquely identifies a known threat. The logic is identical to YARA rule matching: scan the binary, compare against the database, flag on match.

```c
typedef struct {
    uint8_t  *pattern;
    size_t    pattern_len;
    uint32_t  offset;       // file offset, or 0 for any position
    char     *threat_name;
} av_signature_t;

int scan_file(uint8_t *file_buf, size_t file_len, av_signature_t *sigs, int sig_count) {
    for (int i = 0; i < sig_count; i++) {
        uint32_t start = sigs[i].offset ? sigs[i].offset : 0;
        uint32_t end   = sigs[i].offset ? sigs[i].offset : (file_len - sigs[i].pattern_len);

        for (uint32_t j = start; j <= end; j++) {
            if (memcmp(file_buf + j, sigs[i].pattern, sigs[i].pattern_len) == 0)
                return 1; // match
        }
    }
    return 0;
}
```

The structural weakness is obvious: change a single byte and you produce a different hash. Inject a NOP sled before the entry point and the byte sequence no longer matches. This is a blocklist, not intelligence. It only catches what has already been seen and catalogued.

**What it sees:** known byte patterns on disk.  
**What it misses:** anything not in the database, including novel malware and modified variants of known tools.

### Heuristic-Based Detection

Signature detection fails against anything new. Heuristic detection compensates by analyzing intent rather than identity. The engine disassembles the binary, traces execution paths, builds a call graph, and searches for patterns that resemble malicious behavior.

The most common flag: a PE that imports `VirtualAlloc`, `WriteProcessMemory`, and `CreateRemoteThread` together with no other significant imports. The combination implies shellcode injection. The engine does not need to know the payload. It reads the import table and infers what the binary is about to do.

```python
# Simplified heuristic scoring logic
SUSPICIOUS_APIS = {
    "VirtualAlloc":        10,
    "VirtualAllocEx":      10,
    "WriteProcessMemory":  15,
    "CreateRemoteThread":  15,
    "OpenProcess":          8,
    "VirtualProtect":       8,
    "NtUnmapViewOfSection": 12,
    "LoadLibraryA":         5,
    "GetProcAddress":       5,
}

THRESHOLD = 30  # flag above this score

def score_imports(import_list):
    score = 0
    for api in import_list:
        score += SUSPICIOUS_APIS.get(api, 0)
    return score

def heuristic_scan(import_list):
    score = score_imports(import_list)
    return score >= THRESHOLD
```

The engine also looks at structural anomalies: unusually high entropy sections (suggesting encryption or compression), a PE header that claims to be a DLL but has an executable extension, or a section with both write and execute permissions.

**What it sees:** suspicious API combinations and structural anomalies in the binary on disk.  
**What it misses:** obfuscated imports resolved at runtime, indirect API calls, and behavior that only manifests during execution.

### Behavioral Detection

Heuristics analyze static structure. Behavioral detection executes the binary inside an emulated sandbox and watches what actually happens at runtime.

The sandbox monitors system calls. It tracks file system operations, registry writes, network connections, and process creation. The detection rules describe sequences: allocate executable memory, write into it, execute it as a thread. Open a socket, receive data, spawn a child process. Any sequence that matches a known attack pattern triggers a flag.

```
sandbox trace (simplified):
  [0.001s] NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE, size=0x1000)  -> FLAGGED
  [0.002s] NtWriteVirtualMemory(dest=allocated_region, ...)
  [0.003s] NtCreateThreadEx(start=allocated_region, ...)                  -> FLAGGED
```

This is exactly why static obfuscation alone is not enough. A crypter hides the payload on disk. The sandbox decrypts it, watches it execute, and catches it anyway. The behavior exposes you regardless of what the file looks like at rest.

The behavioral layer also looks for sandbox evasion. A sample that checks the number of running processes, queries screen resolution for a non-standard value, reads the CPUID instruction to detect virtualization, or sleeps for minutes before doing anything is treated with additional suspicion. If your malware detects it is inside a sandbox and stays dormant, it evades behavioral analysis but also fails to execute during the engagement.

**What it sees:** runtime behavior, system call sequences, API call chains.  
**What it misses:** evasion-aware malware that detects the sandbox environment and stays clean; payloads that require specific environmental conditions to activate.

### Machine Learning Detection

Microsoft Defender runs two ML components. A local client engine builds models from features extracted from the file: import counts, section entropy, PE header metadata, string patterns. A cloud engine analyzes metadata submitted from every endpoint running Defender worldwide.

When the local model produces a low-confidence verdict, the sample is submitted to the cloud. The cloud engine processes it against a much larger dataset and returns a final verdict. The feedback loop is global: a new sample flagged on one endpoint trains the model for every endpoint everywhere.

This is why disabling sample submission before testing is not optional. Every payload you run against Defender while submission is enabled goes directly into Microsoft's training pipeline. Your tooling gets signatures built against it automatically.

Before testing, disable it explicitly:

```powershell
Set-MpPreference -SubmitSamplesConsent 2
```

Or via the registry:

```
HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet
  SpynetReporting      -> 0
  SubmitSamplesConsent -> 2
```

**What it sees:** statistical features of files and runtime behavior, correlated across millions of endpoints.  
**What it misses:** samples sufficiently different from anything in the training data; behavior that mimics legitimate applications closely enough to fall below the confidence threshold.

### AMSI: The Layer Most People Miss

Since Windows 10, Microsoft ships AMSI (Antimalware Scan Interface): a standardized API that allows AV engines to inspect content at runtime before execution. PowerShell, JScript, VBScript, and the .NET CLR call into AMSI before executing any script content.

```c
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,       // script content in memory, after decoding
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result       // AMSI_RESULT_DETECTED if malicious
);
```

The critical point: AMSI does not scan files on disk. It scans the content of a script in memory at the exact moment it is about to execute. Base64-encoded PowerShell still gets caught because AMSI receives the decoded string, not the encoded one. Obfuscation at the script layer does not help if the script decodes cleanly before running.

AMSI hooks directly into the PowerShell pipeline. Every string passed to `Invoke-Expression`, every script block, every dynamic execution path passes through `AmsiScanBuffer` before the interpreter sees it.

```
PowerShell execution flow:

  [script input]
       |
  [parser]
       |
  [AmsiScanBuffer] <-- AV engine scans here
       |
  [interpreter]    <-- execution only reaches here if AMSI returns clean
```

**What it sees:** decoded script content in memory, immediately before execution.  
**What it misses:** nothing at the script level, unless the interface itself is patched before the content reaches it.

## The Foundation

Each detection layer was built to compensate for the failure of the one before it. Signatures failed against novel malware, so heuristics were added. Heuristics failed against runtime-only behavior, so sandboxes were added. Sandboxes failed against evasion-aware samples, so ML was added. ML failed against script-based attacks, so AMSI was added.

The pattern is consistent: every evasion technique that became widespread eventually got a detection layer built against it. Understanding why each layer exists, and what assumption it relies on, is what tells you where it breaks. That is the only foundation evasion is built on.
