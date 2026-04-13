---
layout: page
title: "AMSI Internals: How Script Content is Inspected"
---

# AMSI Internals: How Script Content is Inspected

The techniques covered so far address detection at the binary level: signature matching, heuristic analysis, behavioral monitoring of native API calls. They assume the payload is compiled code. When the payload is a script, PowerShell, VBScript, JScript, a macro, or any interpreted content, a different inspection mechanism operates: the Antimalware Scan Interface (AMSI).

AMSI is not a scanner. It is a bridge. It provides a standardized API that script hosts call to submit content for inspection, and it routes that content to whatever antimalware provider is registered on the system. Understanding how the bridge is built and where the content flows is necessary before any bypass attempt is coherent.

## The Problem AMSI Solves

Before AMSI, signature-based detection operated on files. A PowerShell script downloaded over the network and executed without touching disk as a string passed to `Invoke-Expression` produced no file for the scanner to examine. The payload could be heavily obfuscated on disk (or not on disk at all) and the content that actually executed was never inspected.

AMSI moves the inspection point to the moment of execution. The script host, PowerShell, receives the content, passes it to AMSI before executing it, and only proceeds if the scan returns clean. The scanner sees the content in its final form, after any download, decoding, or deobfuscation the loader performed. Obfuscating the script is irrelevant if the executed content is submitted to AMSI in plaintext.

## Architecture

AMSI has four participants.

**The AMSI API** lives in `amsi.dll`, loaded into every host process that uses it. It exposes the functions the host calls: `AmsiInitialize`, `AmsiOpenSession`, `AmsiScanBuffer`, `AmsiScanString`, `AmsiCloseSession`, and `AmsiUninitialize`.

**The host** is any application that submits content for scanning. PowerShell, the Windows Script Host, the Office VBA engine, .NET, and WMI are all built-in hosts. Third-party applications can also call the AMSI API directly.

**The provider** is the antimalware product registered on the system. On a default Windows installation, Windows Defender is the AMSI provider. Third-party AVs replace or supplement it. The provider implements a COM interface (`IAntimalwareProvider`) and registers itself under a known registry key.

**The registry** at `HKLM\SOFTWARE\Microsoft\AMSI\Providers` lists every registered AMSI provider by CLSID. When `AmsiInitialize` runs, it enumerates this key, instantiates each provider via COM, and stores the provider interfaces in the AMSI context structure.

## The Scan Flow

A PowerShell session initializing AMSI follows this sequence:

```
powershell.exe starts
  |
  v
AmsiInitialize(L"PowerShell", &amsi_context)
  -- creates AMSI_CONTEXT
  -- enumerates providers from registry
  -- instantiates each provider via CoCreateInstance
  -- stores provider interfaces in amsi_context
  |
  v
AmsiOpenSession(amsi_context, &amsi_session)
  -- creates AMSI_SESSION within the context
  -- session groups related scans (e.g., all content in one pipeline run)
  |
  v
[user types or loads a script]
  |
  v
AmsiScanBuffer(
    amsi_context,
    script_content_ptr,
    content_length,
    L"script_block_name",
    amsi_session,
    &result
)
  -- calls each registered provider's IAntimalwareProvider::Scan method
  -- provider receives the raw content buffer
  -- provider returns AMSI_RESULT value
  -- if any provider returns AMSI_RESULT_DETECTED: block execution
  -- if all return clean: allow execution
  |
  v
AmsiCloseSession(amsi_context, amsi_session)
```

The critical function is `AmsiScanBuffer`. It is called with a pointer to the content buffer and its length, and it synchronously returns a result before the host executes anything.

## AmsiScanBuffer Signature

```c
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,   // context from AmsiInitialize
    PVOID        buffer,        // pointer to content to scan
    ULONG        length,        // length of content in bytes
    LPCWSTR      contentName,  // display name for logging
    HAMSISESSION amsiSession,  // session from AmsiOpenSession
    AMSI_RESULT *result        // output: scan result
);
```

The return value is an `HRESULT` indicating whether the scan completed. The actual detection decision is in `*result`. The host checks `AmsiResultIsMalware(*result)` which evaluates to true when `result >= AMSI_RESULT_DETECTED`.

## Result Codes

```c
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN               = 0,
    AMSI_RESULT_NOT_DETECTED        = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479,
    AMSI_RESULT_DETECTED            = 32768
} AMSI_RESULT;

// Host uses this macro to check the result:
#define AmsiResultIsMalware(r) \
    ((r) >= AMSI_RESULT_DETECTED)
```

A result of `AMSI_RESULT_CLEAN` or `AMSI_RESULT_NOT_DETECTED` allows execution. Anything at or above `AMSI_RESULT_DETECTED` blocks it. The gap between `AMSI_RESULT_NOT_DETECTED` (1) and `AMSI_RESULT_DETECTED` (32768) is significant: there are many result codes in between that represent administrative blocks rather than detections. A bypass that forces the result to any value below 32768 succeeds.

## The AMSI Context Structure

`AMSICONTEXT` is an opaque handle to the caller. Internally it is a pointer to an undocumented structure. Reversing `amsi.dll` reveals the layout:

```c
// Approximate layout -- offsets verified on specific Windows versions
// and subject to change across updates
typedef struct _AMSI_CONTEXT {
    DWORD       Signature;        // 0x49534D41 ("AMSI")
    PWSTR       AppName;          // L"PowerShell" or caller-supplied name
    // ... padding
    PVOID       *Providers;       // array of IAntimalwareProvider pointers
    DWORD       ProviderCount;
    // ... additional fields
} AMSI_CONTEXT_INTERNAL;
```

The `Signature` field at offset 0 contains the ASCII bytes of "AMSI" (`0x49534D41`). This field is checked at the start of `AmsiScanBuffer`: if the signature is not present, the function fails early. The bypass implications of this are covered in the next article.

## Provider Communication

Each provider implements `IAntimalwareProvider`:

```cpp
interface IAntimalwareProvider : IUnknown {
    HRESULT Scan(
        IAmsiStream *stream,   // stream interface for reading content
        AMSI_RESULT *result
    );
    void CloseSession(ULONGLONG session);
};
```

The provider receives an `IAmsiStream` interface rather than a raw buffer. It calls `IAmsiStream::Read` to retrieve content and `IAmsiStream::GetAttribute` to query metadata (content name, session ID, content size, app name). The provider's scan logic is entirely its own: it may call into a local signature database, send a hash to a cloud service, or apply heuristics. AMSI does not prescribe how the scan is performed.

After all providers return, `AmsiScanBuffer` aggregates results. The highest result value from any provider is what the host receives. If one provider returns `AMSI_RESULT_DETECTED` and another returns `AMSI_RESULT_CLEAN`, the output is `AMSI_RESULT_DETECTED`.

## AMSI in Different Hosts

PowerShell is the most targeted host, but AMSI runs in several others.

**Windows Script Host** (`wscript.exe`, `cscript.exe`) submits VBScript and JScript content. Any script executed via `wscript` or `cscript` passes through AMSI before execution.

**Office VBA** submits macro content when macros execute. The AMSI scan runs against the decompiled VBA source, not the raw compressed binary format stored in the document. The scanner sees readable code.

**.NET / CLR** calls AMSI for assembly loads in certain contexts. The integration point depends on the .NET version and host configuration.

**Custom hosts** can call the AMSI API directly. Security products, sandboxes, and custom script execution environments integrate AMSI as a first inspection layer.

## The ETW Connection

Every `AmsiScanBuffer` call emits an ETW event through the `Microsoft-Windows-AMSI` provider. The event contains the content name, the session ID, the app name, and the scan result. An EDR consuming this provider receives a record of every AMSI scan: what was submitted, by which application, and what the result was.

Patching `EtwEventWrite` silences this telemetry. From the ETW consumer's perspective, scans are happening but producing no events. This matters when the bypass technique modifies the result rather than the content: even if AMSI returns clean, the EDR would normally see the scan event and could correlate the content submitted with known-bad patterns independently. Without the ETW event, that correlation does not happen.

## What AMSI Does Not Cover

AMSI inspects content at submission time. It does not monitor what the executed code does afterward. A PowerShell script that passes AMSI clean and then downloads and runs a second stage is not re-inspected at the second stage unless the second stage also passes through a host that calls `AmsiScanBuffer`.

Scripts that construct their payload at runtime from innocuous parts, assembling the final content through string operations and then calling `[System.Reflection.Assembly]::Load` or `Invoke-Expression`, submit only the final assembled content to AMSI at the moment of execution. The assembly operation itself is not scanned. This is why content submitted to AMSI is always the final, decoded, ready-to-execute form.

## The Inspection Point in PowerShell

PowerShell's integration is the deepest. Every script block that enters the PowerShell execution pipeline is scanned. This includes:

- Scripts loaded from files (`Import-Module`, dot-source)
- Strings passed to `Invoke-Expression`
- Dynamic code generated at runtime
- Downloaded content executed via `IEX (New-Object Net.WebClient).DownloadString(...)`

The scan happens after the content is fully assembled but before the first instruction executes. The `ScriptBlock` object is created in memory with the full source text, AMSI scans that text, and only if the result is clean does the PowerShell execution engine compile and run it.

This is the point the bypass must address. Any technique that modifies the scan outcome, the content submitted, or the inspection path itself operates here.
