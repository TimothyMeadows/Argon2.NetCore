# Argon2.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet](https://img.shields.io/nuget/v/Argon2.NetCore.svg)](https://www.nuget.org/packages/Argon2.NetCore/)

`Argon2.NetCore` is a .NET implementation of the Argon2 password/key derivation function (PHC winner) by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich. This package is optimized to work with [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) so sensitive material can stay in pinned buffers for better memory-handling control.

---

## Installation

```bash
dotnet add package Argon2.NetCore
```

```powershell
Install-Package Argon2.NetCore
```

NuGet package page:
https://www.nuget.org/packages/Argon2.NetCore/

---

## Quick start

```csharp
using System;
using System.Security.Cryptography;
using Argon2.NetCore;
using PinnedMemory;

var salt = new byte[16];
var secret = new byte[32];
RandomNumberGenerator.Fill(salt);
RandomNumberGenerator.Fill(secret);

using var keyPin = new PinnedMemory<byte>(secret, false);
using var argon2 = new Argon2(keyPin, salt)
{
    // Argon2i (IndependentAddressing) by default.
    // Set DependentAddressing for Argon2d.
    Addressing = Argon2.AddressType.IndependentAddressing,

    HashLength = 32,
    MemoryCost = 65536, // 64 MiB (value is KiB)
    TimeCost = 3,
    Lanes = 4,
    Threads = 2
};

// Optional: include additional context bytes in the hash input.
var message = new byte[] { 0x63, 0x61, 0x77 }; // "caw"
argon2.UpdateBlock(message, 0, message.Length);

using var hash = new PinnedMemory<byte>(new byte[argon2.GetLength()]);
argon2.DoFinal(hash, 0);

Console.WriteLine(Convert.ToHexString(hash.ToArray()));
```

Additional sample code is available in `Argon2.NetCore.Examples/Program.cs`.

---

## Constructor

```csharp
Argon2(PinnedMemory<byte> key, byte[] salt, byte[] associatedData = null)
```

### Parameters

- `key`: secret key / password bytes (required).
- `salt`: unique random salt bytes (required, minimum 8 bytes).
- `associatedData`: optional associated bytes mixed into derivation.

---

## Configuration options

Set these on the `Argon2` instance before calling `DoFinal`.

- `Addressing`
  - `IndependentAddressing` (`Argon2i` behavior; default)
  - `DependentAddressing` (`Argon2d` behavior)
- `HashLength` (`int`)
  - Number of output bytes.
  - Minimum value: `4`.
- `MemoryCost` (`int`)
  - Memory cost in **KiB**.
  - Example: `65536` = 64 MiB.
- `TimeCost` (`int`)
  - Number of iterations/passes over memory.
- `Lanes` (`int`)
  - Number of lanes (parallelism level).
- `Threads` (`int`)
  - Number of worker threads used by the implementation.

---

## API reference

- `int GetLength()`
  - Returns currently configured output length.
- `void Update(byte input)`
  - Appends one byte to the message input.
- `void UpdateBlock(byte[] input, int inOff, int len)`
  - Appends part of a byte array to the message input.
- `void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)`
  - Appends a pinned byte buffer to the message input.
- `void DoFinal(PinnedMemory<byte> output, int outOff)`
  - Computes derived output and writes to the provided pinned output buffer.
- `void Reset()`
  - Resets internal state for another run while retaining key/salt.
- `void Dispose()`
  - Clears key/salt state and frees resources.

---

## Best practices

### 1. Always use a unique, random salt

- Use at least 16 bytes of cryptographically secure randomness.
- Never reuse a salt for different secrets when avoiding correlation matters.

### 2. Tune cost parameters for your environment

- Start from:
  - `MemoryCost`: 64 MiB to 256 MiB (`65536` to `262144` KiB)
  - `TimeCost`: `2` to `4`
  - `Lanes`: number of physical cores (or a smaller operational cap)
- Benchmark in production-like conditions and target a derivation time that balances security and user latency.

### 3. Prefer Argon2i-style addressing when side-channel concerns matter

- `IndependentAddressing` (default) maps to Argon2i-style memory addressing and is generally safer for password hashing scenarios.
- Use `DependentAddressing` only when you specifically need Argon2d-style behavior.

### 4. Handle secrets as pinned memory where possible

- Keep password/key data in `PinnedMemory<byte>` while hashing.
- Dispose of `Argon2` and pinned buffers promptly to reduce lifetime of sensitive data.

### 5. Size output intentionally

- 32 bytes is a common default for key derivation.
- Use larger output (for example 64 bytes) only when your protocol needs it.

### 6. Store metadata alongside derived values

When persisting hashes, store:

- Algorithm identifier (`Argon2` variant/addressing mode)
- `MemoryCost`, `TimeCost`, `Lanes`, `HashLength`
- Salt
- Hash output

This ensures future verification and migration remain possible.

### 7. Validate operational limits

- Very high memory/thread settings can exhaust container/host resources.
- Use load testing to verify worst-case concurrency and avoid denial-of-service through excessive KDF pressure.

---

## Notes

- `DoFinal` requires an output buffer large enough for `HashLength` at the given offset.
- `salt` must be at least 8 bytes.
- Parameter validation throws exceptions for invalid values (e.g., non-positive costs/lanes/threads).

---

## License

MIT. See [LICENSE](LICENSE).
