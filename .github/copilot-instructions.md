# TronAesCrypt Development Guide

## Project Overview

This is a C# implementation of the [AES Crypt v2 file format](https://www.aescrypt.com/aes_file_format.html). The solution is split into:

- **TronAesCrypt.Core** - Reusable library implementing AES-256 encryption/decryption (published as NuGet package)
- **TronAesCrypt.Main** - Console application `AesCrypt.exe` (uses CommandLineParser)
- **TronAesCrypt.Core.Tests** & **TronAesCrypt.Main.Tests** - xUnit test projects

**Target Framework**: .NET 10.0  
**C# Language Version**: C# 13

> **Note**: For comprehensive C# and .NET coding standards, see [C# Coding Standards](instructions/csharp-coding-standards.instructions.md)

## Architecture & Key Components

### Core Encryption Flow (`AesCrypt.cs`)

The implementation follows a multi-layer security model:

1. **Password Stretching**: User password → SHA-256 hashed 8192 times with IV (`StretchPassword`)
2. **Key Hierarchy**:
   - `ivMainKey` - IV for encrypting the actual encryption key
   - `internalKey` - 32-byte key used for data encryption
   - `ivData` - IV for data encryption
3. **Double HMAC-SHA256**: One for encrypted key/IV, one for encrypted data
4. **Manual Padding**: Custom PKCS#7-like padding (last byte stores modulo 16)

**WHY**: This matches the AES Crypt v2 spec exactly - interoperability with other AES Crypt implementations is critical.

### Header Format (`AesCryptHeader.cs`)

- Magic bytes: `"AES"` + version byte `2` + reserved byte `0`
- Extensions: `CREATED_BY` + app name, 128-byte container, end-of-extensions tag (`0x00 0x00`)
- All extension lengths are big-endian 16-bit values

### String Encoding Conventions

- **UTF-8** for file format strings (headers, extensions) via `GetUtf8Bytes()`
- **UTF-16 LE** for password hashing via `GetUtf16Bytes()` - matches AES Crypt spec

## Build & Test Commands

```bash
# Standard workflow
dotnet restore
dotnet build -c Release
dotnet test -c Release

# Pack library (auto-builds on build due to GeneratePackageOnBuild=true)
dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj
```

**Output**: `TronAesCrypt.Main/bin/Release/net10.0/AesCrypt.exe` (or `AesCrypt.dll` on non-Windows)

## Testing Patterns

### xUnit + AutoFixture

All test projects use:

- **AutoFixture** for randomized test data
- **Moq** for mocking (though rarely needed - mostly integration tests)
- **xUnit** as test framework with built-in assertions

### Critical Test Pattern (`FileFormatTests.cs`)

Round-trip testing with various file sizes (`empty`, `xs`, `s`, `l`, `xl`, `xxl`) to catch padding edge cases:

```csharp
crypter.EncryptFile(file, encryptedFileName, Password, 64 * 1024);
crypter.DecryptFile(encryptedFileName, decryptedFileName, Password, 64 * 1024);
Assert.Equal(fileName.AsSha256OfFile(), decryptedFileName.AsSha256OfFile());
```

**WHY**: Padding bugs only manifest with specific file sizes (multiples of 16 bytes).

## Project-Specific Conventions

### Namespace Structure

- Root: `TRONSoft.TronAesCrypt.Core` (note: TRONSoft, not TronSoft)
- Tests: `TRONSoft.TronAesCrypt.Core.Tests`
- Main app: `TronAesCrypt.Main` (no TRONSoft prefix)

### Resource Strings

Error messages live in `.resx` files compiled via `ResXFileCodeGenerator`:

- `Resources.TheFileIsCorrupt`
- `Resources.NotAnAescryptFile`
- `Resources.OnlyAesCryptVersion2IsSupported`

### Version Management

- **Directory.Build.props** - Shared assembly version across all projects (`1.0.2.0`)
- **TronAesCrypt.Core.csproj** - Separate NuGet package version (`1.0.3.0`)
- **AesCryptHeader.cs** - Hardcoded app version for file headers (`0.1.0`)

## Critical Implementation Details

### Buffer Size Requirements

**MUST** be a multiple of 16 (AES block size). Default `bufferSize = 16`, but CLI/tests use `64 * 1024` for performance.

### Crypto Library Usage

- `Aes.Create()` with manual configuration:
  - `KeySize = 256 bits`, `BlockSize = 128 bits`
  - `Mode = CBC`, `Padding = None` (manual padding!)
- HMAC-SHA256 for integrity (NOT encryption-then-MAC, it's encrypt-then-HMAC per spec)

### Stream Processing Pattern

Encrypt/decrypt methods operate on `Stream` abstractions, not just files. This enables:

- In-memory encryption for testing (`MemoryStream`)
- Network stream encryption (potential future use)
- Large file handling without loading entire file

## Common Pitfalls

1. **Don't use `PaddingMode.PKCS7`** - The AES Crypt spec uses a custom scheme (last byte = padding length)
2. **UTF-16 LE for passwords** - Not UTF-8! (`GetUtf16Bytes()`)
3. **Big-endian extension lengths** - Use `Array.Reverse()` on little-endian systems
4. **HMAC before padding removal** - Verify HMAC on encrypted data, THEN remove padding

## CLI Usage Examples

```bash
# Encrypt
AesCrypt.exe -e -f plain.txt -o plain.txt.aes -p Password1234

# Decrypt
AesCrypt.exe -d -f encrypted.aes -o decrypted.txt -p Password1234
```

## Extension Points

When adding features, maintain AES Crypt v2 compatibility:

- New extensions go in `AesCryptHeader.WriteExtensions()`
- Must update `ReadHeader()` to skip unknown extensions
- Test against reference implementations (Java, C, Python versions)

## Debugging & Troubleshooting

### Common Error Scenarios

**"The file is corrupt" (`Resources.TheFileIsCorrupt`)**

- Thrown when HMAC verification fails or file structure is invalid
- Check: Wrong password, file truncated, or non-AES Crypt file
- Debug: Verify file header magic bytes ("AES" + version 2)

**"Buffer size must be a multiple of AES block size"**

- Always use `bufferSize % 16 == 0` when calling encrypt/decrypt methods
- CLI defaults to `64 * 1024` for good performance

**Padding Issues**

- Manifest as decryption failures or extra bytes at end of file
- Test with files of exact multiples of 16 bytes (edge case)
- The last byte stores `16 - (fileSize % 16)` or `0` if exact multiple

### Debugging Tips

**Inspect encrypted file structure:**

```bash
# View file header in hex
xxd -l 256 encrypted.aes
# Should see: 41 45 53 02 00 ... (AES + version 2 + reserved)
```

**Test interoperability:**

- Encrypt with this implementation, decrypt with official AES Crypt tools
- Vice versa: encrypt with official tools, decrypt with TronAesCrypt
- Download reference implementation: https://www.aescrypt.com/download/

**Memory stream debugging:**

```csharp
// Test encryption logic without file I/O
using var input = new MemoryStream(testData);
using var output = new MemoryStream();
crypter.EncryptStream(input, output, password, 16);
// Inspect output.ToArray() for header/structure validation
```

## NuGet Package Publishing

### Automatic Package Generation

The `TronAesCrypt.Core` project builds a NuGet package on every build due to:

```xml
<GeneratePackageOnBuild>true</GeneratePackageOnBuild>
```

### Package Contents

- Assembly: `TRONSoft.TronAesCrypt.Core.dll`
- README.md and LICENSE automatically included via `.csproj` `<None Include>` items
- Package metadata from `Directory.Build.props` (author, copyright) and project file (version, description)

### Version Update Workflow

1. Update `<PackageVersion>` in `TronAesCrypt.Core.csproj` (e.g., `1.0.4.0`)
2. Update `<AssemblyVersion>` in `Directory.Build.props` if needed (affects all projects)
3. Update `AesCryptHeader.Version` constant if file format changes
4. Build: `dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj`
5. Package appears in `TronAesCrypt.Core/bin/Release/TRONSoft.TronAesCrypt.Core.{version}.nupkg`

### Publishing Checklist

- [ ] All tests pass (`dotnet test -c Release`)
- [ ] Round-trip tests verify with all file sizes (empty through xxl)
- [ ] Version numbers updated consistently
- [ ] README reflects any API changes
- [ ] Test interoperability with official AES Crypt tools

## Advanced Testing Patterns

### File Size Test Matrix (`FileFormatTests._fileInfo`)

```csharp
["empty"] = 0,      // Edge case: no data
["xs"] = 16,        // Exactly 1 AES block
["s"] = 230,        // Multiple blocks + padding
["l"] = 143526,     // Large file
["xl"] = 1616161,   // Very large
["xxl"] = 46851123  // Stress test
```

**WHY**: Different file sizes exercise different padding code paths.

### SHA-256 Verification Pattern

Tests use `fileName.AsSha256OfFile()` extension method to verify decrypted output matches original:

```csharp
Assert.Equal(originalFile.AsSha256OfFile(), decryptedFile.AsSha256OfFile());
```

This catches subtle corruption that byte-by-byte comparison might miss.

### Process-Based CLI Testing (`AesCryptProcessRunner.cs`)

Main.Tests project spawns actual `AesCrypt.exe` process to test:

- Command-line argument parsing (CommandLineParser integration)
- Exit codes and error messages
- Real-world file I/O behavior

## Code Style & Conventions

### Extension Methods Pattern

The codebase favors extension methods for utilities:

- `StringExtensions.cs`: `GetUtf8Bytes()`, `GetUtf16Bytes()`
- `BytesExtensions.cs`: `GetUtf8String()`
- `ArrayExtensions.cs`: Array manipulation helpers
- Test helpers: `AsSha256OfFile()` for file comparison

### Resource Strings Over String Literals

All user-facing error messages use `Resources.{MessageName}`:

- Enables future localization
- Centralized error message management
- Type-safe via generated `Resources.Designer.cs`

### Stream-First API Design

Public APIs accept `Stream` parameters, file-based methods are convenience wrappers:

```csharp
public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 16)
```

**WHY**: Maximizes reusability and testability.
