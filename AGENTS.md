# TronAesCrypt - AI Agent Guide

**What:** C# implementation of [AES Crypt Stream Format v2](https://www.aescrypt.com/aes_file_format.html)  
**Target:** .NET 10.0, C# 14  
**License:** MIT

> **Note**: Implements Stream Format **v2** (not v3). V3 has stronger PBKDF2-HMAC-SHA512 KDF, but this uses v2 for compatibility.

## 📖 Documentation

**→ For comprehensive guidance, see [.github/copilot-instructions.md](.github/copilot-instructions.md)**

That file includes:
- Stream Format v2 specification (complete byte layout)
- Architecture & encryption flow details
- Project-specific conventions (namespaces, versions, resources)
- Critical implementation details (buffer sizes, crypto, padding)
- Testing patterns & debugging tips
- NuGet publishing workflow
- V3 upgrade path (future enhancement)

**→ Coding standards: [.github/instructions/](.github/instructions/)**
- `csharp-coding-standards.instructions.md` - C# 14 conventions
- `clean-code.instructions.md` - General principles

## 🏗️ Project Structure

```
TronAesCrypt.Core/          # Library (published as NuGet package)
TronAesCrypt.Main/          # CLI application (AesCrypt.exe)
TronAesCrypt.Core.Tests/    # xUnit tests for Core
TronAesCrypt.Main.Tests/    # xUnit tests for CLI
```

## ⚡ Quick Commands

```bash
# Build & Test
dotnet restore
dotnet build -c Release
dotnet test -c Release

# Run CLI
AesCrypt.exe -e -f input.txt -o output.aes -p Password1234

# Pack NuGet (auto-generates on build)
dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj
```

## 🔑 Key Points

- **Stream Format v2 implementation** - 8,192 SHA-256 iterations for KDF (not v3's PBKDF2)
- **Buffer sizes must be multiples of 16** (AES block size)
- **UTF-16 LE for passwords**, UTF-8 for file format strings
- **Custom padding with modulo byte** (not PKCS#7 - that's v3)
- **Stream-first API** - file methods are convenience wrappers
- **Namespace**: `TRONSoft.TronAesCrypt.Core` (note: TRONSoft, not TronSoft)
