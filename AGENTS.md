# TronAesCrypt - AI Agent Guide

**What:** C# implementation of [AES Crypt Stream Format v3](https://www.aescrypt.com/aes_file_format.html)  
**Target:** .NET 10.0, C# 14  
**License:** MIT

> **Note**: Implements Stream Format **v3** (PBKDF2-HMAC-SHA512, PKCS7 padding).

**→ For comprehensive guidance, see [.github/copilot-instructions.md](.github/copilot-instructions.md)**

### Stream Format v3 Specification

This implementation follows [AES Crypt v3](https://www.aescrypt.com/aes_file_format.html):

1. **Header**: "AES" + Version (0x03) + Reserved (0x00).
2. **Extensions**: Flexible metadata (CREATED_BY, etc.).
3. **Iteration Count**: 4-byte big-endian integer (default: 300,000).
4. **Key Derivation**: PBKDF2-HMAC-SHA512.
   - Salt: 16-byte random IV.
   - Iterations: Configurable (min 10,000).
5. **Encryption**: AES-256 CBC Mode.
6. **Padding**: Standard **PKCS#7** (unlike v2's custom modulo padding).
7. **HMAC**:
   - HMAC-SHA256(encrypted_keys || 0x03) for header integrity.
   - HMAC-SHA256(ciphertext) for data integrity.

**Backward Compatibility**: The library can decrypt v2 files (SHA-256 stretching, modulo padding), but only writes v3 files by default.

### Coding Standards

Refer to [`csharp-coding-standards.instructions.md`][csharp-standards] and [`clean-code.instructions.md`][clean-code] for comprehensive C# 14 conventions and design principles.

**Key Conventions:**
- **Namespaces**: File-scoped namespace declarations (C# 10+)
- **Naming**: PascalCase for classes/methods, camelCase for locals, `_` prefix for private fields
- **Braces**: Always required, even for single-statement blocks
- **Pattern Matching**: Prefer modern C# patterns (`is`, `switch expressions`) over traditional conditionals
- **Async**: Use `async`/`await` end-to-end; suffix async methods with `Async`
- **Comments**: Explain WHY only; never add section headers, closing-brace, or journal comments
- **InternalsVisibleTo**: Expose internal logic (e.g., `CryptRunner`) to test projects

[csharp-standards]: .github/instructions/csharp-coding-standards.instructions.md
[clean-code]: .github/instructions/clean-code.instructions.md

## 🏗️ Project Structure

```text
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

# Pack NuGet (auto-generates on build)
dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj
```

## 🔑 Key Points

- **Stream Format v3** - PBKDF2-HMAC-SHA512 with 300,000 iterations (not v2's SHA-256)
- **PKCS7 padding** - Standard block padding (unlike v2's custom modulo byte)
- **AES-256 CBC** - Block cipher mode with IV (salt is 16-byte random IV in headers)
- **UTF-16 LE for passwords** (internal strings), UTF-8 for file format strings
- **Stream-first API** - CLI uses streams for I/O flexibility; file methods are convenience wrappers
- **Braces mandatory** - always use braces for `if`, `else`, `for`, `foreach`, `while`, and `using` blocks, even for a single statement
- **Comments** - explain WHY only — never add section-header, closing-brace, journal, mandated, or banner comments; remove them on sight
- **Namespace**: `TRONSoft.TronAesCrypt.Core` (note: TRONSoft, not TronSoft)
