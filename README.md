# Argon2.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Argon2.NetCore.svg)](https://www.nuget.org/packages/Argon2.NetCore/)

Implementation of Argon2 key derivation function designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich. Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

# Install

From a command prompt
```bash
dotnet add package Argon2.NetCore
```

```bash
Install-Package Argon2.NetCore
```

You can also search for package via your nuget ui / website:

https://www.nuget.org/packages/Argon2.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var iv = new byte[16];
var key = new byte[32];

using var provider = new RNGCryptoServiceProvider();
provider.GetBytes(iv);
provider.GetBytes(key);

using var keyPin = new PinnedMemory<byte>(key, false);
using var argon2 = new Argon2(keyPin, iv)
{
  Addressing = Argon2.AddressType.DependentAddressing,
  HashLength = 64,
  MemoryCost = 65536,
  Lanes = 4,
  Threads = 2,
  TimeCost = 3
};

argon2.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false), 0, 11); // caw caw caw in utf8

using var hash = new PinnedMemory<byte>(new byte[argon2.GetLength()]);
argon2.DoFinal(hash, 0);
```


# Constructor

```csharp
Argon2(PinnedMemory<byte> key, byte[] salt, byte[] associatedData = null)
```

# Options

#### HashLength
Length of hash to output, typically 32, 64.

#### Lanes
Parallelism number of parallel threads, typically 4, or number of cpu cores.

#### Threads
Number of threads to spawn in relation to parallelism. This is typically 1, or number of cpu cores.

#### MemoryCost
Amount of memory (in kibibytes) to use. The more that's used the harder it may be for GPU's to process.

#### TimeCost
Amount of interations to use. The more that's used the harder it may be for CPU's to process.

# Methods

Get the hash output length.
```csharp
int GetLength()
```

Update the hash with a single byte.
```csharp
void Update(byte input)
```

Update the hash with a pinned memory byte array.
```csharp
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
```

Update the hash with a byte array.
```csharp
void UpdateBlock(byte[] input, int inOff, int len)
```

Produce the final hash outputting to pinned memory. Key & salt remain until dispose is called.
```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```

Reset the hash back to it's initial state for further processing. Key & salt remain until dispose is called.
```csharp
void Reset()
```

Clear key & salt, reset hash back to it's initial state.
```csharp
void Dispose()
```
