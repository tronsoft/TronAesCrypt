# TronAesCrypt Development Guide

## Project Overview

This is a C# implementation of the **AES Crypt v3 file format**. The solution is split into:

- **TronAesCrypt.Core** - Reusable library implementing AES-256 encryption/decryption (published as NuGet package)
- **TronAesCrypt.Main** - Console application `AesCrypt.exe` (uses CommandLineParser)
- **TronAesCrypt.Core.Tests** & **TronAesCrypt.Main.Tests** - xUnit test projects

**Target Framework**: .NET 10.0
**C# Language Version**: C# 14

> **Note**: For comprehensive C# and .NET coding standards, see [C# Coding Standards](instructions/csharp-coding-standards.instructions.md)

## Architecture & Key Components

### Core Encryption Flow

The implementation defaults to **Stream Format v3** for encryption but supports reading both v2 and v3.

- **`AesCrypt.cs`**: Facade that delegates to `AesV3Encryptor` for encryption and `AesDecryptorFactory` for decryption.
- **`AesV3Encryptor.cs`**: Implements v3 spec (PBKDF2-HMAC-SHA512, PKCS7 padding).
- **`CryptRunner.cs`** (in Main): Encapsulates CLI logic, allowing dependency injection for testing (e.g., password readers, streams).

### Stream Format v3 Specification

This implementation defaults to **AES Crypt Stream Format v3**.

1.  **Header**: "AES" + Version (0x03) + Reserved (0x00).
2.  **Extensions**: Flexible metadata (CREATED_BY, etc.).
3.  **Iteration Count**: 4-byte big-endian integer (default: 300,000).
4.  **Key Derivation**: PBKDF2-HMAC-SHA512.
    -   Salt: 16-byte random IV.
    -   Iterations: Configurable (min 10,000).
5.  **Encryption**: AES-256 CBC Mode.
6.  **Padding**: Standard **PKCS#7** (unlike v2's custom modulo padding).
7.  **HMAC**:
    -   HMAC-SHA256(encrypted_keys || 0x03) for header integrity.
    -   HMAC-SHA256(ciphertext) for data integrity.

> **Backward Compatibility**: The library can fully decrypt v2 files (SHA-256 stretching, modulo padding), but only writes v3 files by default.

## CLI Usage

The CLI supports positional arguments, piping, and key files.

### Syntax
```bash
AesCrypt.exe [files...] [-o output] [-p password | -k keyfile] [options]
```

### Examples
```bash
# Encrypt file (auto-names to file.txt.aes)
AesCrypt.exe file.txt

# Decrypt file (auto-removes .aes extension)
AesCrypt.exe -d file.txt.aes

# Encrypt with explicit output
AesCrypt.exe file.txt -o encrypted.dat

# Use a key file instead of password
AesCrypt.exe file.txt -k secret.key

# Generate a random key file
AesCrypt.exe -g -k secret.key

# Standard Input/Output (piping)
cat plain.txt | AesCrypt.exe - -o - > encrypted.aes
```

## Build & Test Commands

```bash
# Standard workflow
dotnet restore
dotnet build -c Release
dotnet test -c Release

# Run specific test
dotnet test --filter "FullyQualifiedName~FileFormatTests"

# Pack library (auto-builds on build)
dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj
```

**Output**: `TronAesCrypt.Main/bin/x64/Release/net10.0/linux-x64/AesCrypt.dll`

## Project-Specific Conventions

### Coding Standards
Refer to [C# Coding Standards](instructions/csharp-coding-standards.instructions.md) for general rules. Specific additions:

- **`InternalsVisibleTo`**: Used to expose internal logic (like `CryptRunner`) to test projects.
- **Control Flow**: Always use braces `{ }`, even for single-line statements.
- **Pattern Matching**: Prefer modern C# pattern matching (e.g., `is`, `switch`) for type checks and conditions.

### Resource Management
- **Resources.resx**: Stores all user-facing strings/errors.
- **Linux Dev Note**: `ResXFileCodeGenerator` is Windows-only. When modifying `.resx` on Linux, you **MUST** manually update `Resources.Designer.cs` to match.

### Namespace Structure
- Root: `TRONSoft.TronAesCrypt.Core`
- Tests: `TRONSoft.TronAesCrypt.Core.Tests`
- Main: `TronAesCrypt.Main`

## Testing Patterns

### Integration Testing (`AesCryptCommandLineTests.cs`)
Tests run the full CLI logic via `CryptRunner` or spawned processes (`AesCryptProcessRunner`), covering:
- Argument parsing
- Stdin/Stdout piping (`NonDisposingStream` wrappers)
- Key file generation/usage
- Interactive password prompts (via `Func<string>` injection)

### Core Logic (`FileFormatTests.cs`)
Uses `AesCrypt` class directly to test round-trip encryption/decryption with various file sizes to ensure padding handles edge cases (empty, 1 block, 1 byte off, etc.).

## NuGet Package Publishing

- **Automatic Packing**: `<GeneratePackageOnBuild>true` in `.csproj`.
- **Versioning**:
    1. Update `<PackageVersion>` in `TronAesCrypt.Core.csproj`.
    2. Update `AesCryptHeader.Version` if file format changes.
    3. Build Release config.
