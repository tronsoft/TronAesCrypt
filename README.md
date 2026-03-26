# TronAesCrypt
An implementation of [AesCrypt](https://www.aescrypt.com/) in C#. It supports version 2 (read) and version 3 (read/write) of the AesCrypt  stream format. The file formats are described [here](https://www.aescrypt.com/aes_stream_format.html).

## Protocol & Compatibility

This library implements **AES Crypt Stream Format v3** for encrypting `.aes` files and supports **backward compatibility** with v2 for decryption.

### Stream Format v3 (Default for Encryption)
- **Encryption**: AES-256 in CBC mode with PKCS#7 padding
- **Key Derivation**: PBKDF2-HMAC-SHA512 with configurable iterations (default: 300,000)
- **Authentication**: HMAC-SHA256 for encrypted key (with version byte) and ciphertext
- **Extensions**: Supports metadata extensions (e.g., `CREATED_BY`)
- **Minimum footprint**: 140 bytes

### Stream Format v2 (Backward Compatibility - Read Only)
- **Encryption**: AES-256 in CBC mode with custom padding
- **Key Derivation**: SHA-256 iterated 8,192 times with password and IV
- **Authentication**: HMAC-SHA256 for both encrypted key and ciphertext
- **Minimum footprint**: 136 bytes

### Compatibility
✅ **Compatible with**: Official AES Crypt 4.x tools and other v3 implementations  
✅ **Can decrypt**: Stream Format v2 and v3 files  
✅ **Can encrypt**: Stream Format v3 files (with enhanced security)

### Why Stream Format v3?
Stream Format v3 provides significant security improvements over v2:
- **300,000 PBKDF2 iterations** (vs 8,192 SHA-256 iterations) makes brute-force attacks substantially more difficult
- **HMAC includes version byte** to prevent downgrade attacks
- **Standard PKCS#7 padding** improves interoperability

For detailed protocol documentation, see [AES Crypt Stream Format Specification](https://www.aescrypt.com/aes_stream_format.html).

## Projects
- `TronAesCrypt.Core` - Library implementing the AesCrypt v2 (read) and v3 (read/write) stream formats (packaged on build).
- `TronAesCrypt.Main` - Console application (`AesCrypt.exe` / `dotnet AesCrypt.dll`).
- `TronAesCrypt.Core.Tests` & `TronAesCrypt.Main.Tests` - xUnit test projects.

## CLI Usage

### Encrypt / Decrypt a File

```bash
# Encrypt (output auto-named photo.jpg.aes)
AesCrypt.exe -e -p secret photo.jpg

# Decrypt (output auto-named photo.jpg)
AesCrypt.exe -d -p secret photo.jpg.aes

# Specify output path explicitly
AesCrypt.exe -e -p secret -o backup.aes photo.jpg
```

### Interactive Password Prompt

Omit `-p` to be prompted for a password (input is masked):

```bash
AesCrypt.exe -e photo.jpg
# Password: ********
```

### Multiple Files

Encrypt or decrypt multiple files in one command. Each file gets its own auto-generated output name:

```bash
AesCrypt.exe -e -p secret file1.txt file2.txt file3.txt
# produces: file1.txt.aes  file2.txt.aes  file3.txt.aes
```

### Key Files

Generate a random key file, then use it instead of a password:

```bash
# Generate a key file (64-char random UTF-16 LE)
AesCrypt.exe -g -k secret.key

# Encrypt with key file
AesCrypt.exe -e -k secret.key photo.jpg

# Decrypt with key file
AesCrypt.exe -d -k secret.key photo.jpg.aes
```

> **Note**: Keep the key file secret — it replaces your password. Anyone with the key file can decrypt your files.

### stdin / stdout Piping

Use `-` as the input path for stdin, and `-o -` to write to stdout:

```bash
# Encrypt stdin to a file
tar czf - ./documents | AesCrypt.exe -e -p secret -o - - > backup.tar.gz.aes

# Decrypt a file to stdout
AesCrypt.exe -d -p secret -o - backup.tar.gz.aes | tar xzf -

# Encrypt stdin to stdout (full pipe)
echo "hello" | AesCrypt.exe -e -p secret -o - - | AesCrypt.exe -d -p secret -o - -
```

> **Note**: Decrypting from stdin buffers the entire ciphertext in memory before processing (required by the AES Crypt format). For very large files, prefer file-based decryption.

### Command Reference

| Option | Description |
|--------|-------------|
| `-e` / `--encrypt` | Encrypt the specified file(s) |
| `-d` / `--decrypt` | Decrypt the specified file(s) |
| `-g` / `--generate` | Generate a key file (use with `-k`) |
| `-k` / `--keyfile` | Key file path (alternative to `-p`) |
| `-p` / `--password` | Password (omit to be prompted) |
| `-o` / `--output` | Output path (omit to auto-generate; use `-` for stdout) |
| `file(s)` | One or more input files (use `-` for stdin) |

> **Legacy flag**: `-f <file>` is still supported for backward compatibility but is deprecated in favour of the positional argument.

## Library Usage

```csharp
var crypter = new AesCrypt();

// Encrypt with v3 format (default: 300,000 PBKDF2 iterations)
crypter.EncryptFile("plain.txt", "plain.txt.aes", "Password1234", 64 * 1024);

// Encrypt with custom iteration count (more secure but slower)
crypter.EncryptFile("plain.txt", "plain.txt.aes", "Password1234", 64 * 1024, kdfIterations: 500_000);

// Decrypt (automatically detects v2 or v3 format)
crypter.DecryptFile("plain.txt.aes", "plain-decrypted.txt", "Password1234", 64 * 1024);
```

## Breaking Changes in Version 2.0

### Stream Format v3 Encryption (Breaking Change)

Starting with version 2.0, **all new encryptions are written in Stream Format v3 format only**. This is a breaking change for workflows that depend on v2-format `.aes` output.

**Impact:**
- ✅ **Decryption**: TronAesCrypt 2.0 can decrypt BOTH v2 and v3 files (full backward compatibility)
- ❌ **Encryption**: TronAesCrypt 2.0 writes ONLY v3 format (not readable by v2-only tools)
- ✅ **API**: Public API remains compatible with 1.x; `kdfIterations` is an optional parameter

**Migration Options:**
1. **Upgrade downstream tools** to support Stream Format v3 (recommended for security)
2. **Stay on TronAesCrypt 1.x** for encryption if you must produce v2-format output
3. **Use official AES Crypt tools** (https://www.aescrypt.com/) which support both v2 and v3

**Why v3?**
- 37x stronger key derivation (300,000 PBKDF2-HMAC-SHA512 iterations vs 8,192 SHA-256)
- Configurable iteration counts for custom security levels
- HMAC includes version byte to prevent downgrade attacks
- Standard PKCS#7 padding

## Performance Note

Stream format v3 uses 300,000 PBKDF2 iterations by default (vs v2's 8,192 SHA-256 iterations). This significantly improves security against brute-force attacks but makes encryption/decryption slower. For high-security scenarios, consider increasing iterations to 500,000 or 1,000,000.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Error: 'file' does not exist` | Input file not found | Check the path; use quotes for paths with spaces |
| `The file is corrupt` | Wrong password, truncated file, or not an AES Crypt file | Verify the password and that the file is a valid `.aes` file |
| `Error: cannot auto-determine output name` | Decrypting a file without `.aes` extension | Add `-o <output>` to specify the output path |
| `Error: -p and -k are mutually exclusive` | Both `-p` and `-k` supplied | Use only one password source |
| `Error: -o cannot be used with multiple input files` | `-o` combined with multiple positional files | Remove `-o`; output names are auto-generated |

## Build & Test
```bash
dotnet restore
dotnet build -c Release
dotnet test -c Release
```

## Pack
```bash
dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj
```
Generates a NuGet package with README and LICENSE.

## License
MIT License. See `LICENSE`.

## Protocol & Compatibility

This library implements **AES Crypt Stream Format v3** for encrypting `.aes` files and supports **backward compatibility** with v2 for decryption.

### Stream Format v3 (Default for Encryption)
- **Encryption**: AES-256 in CBC mode with PKCS#7 padding
- **Key Derivation**: PBKDF2-HMAC-SHA512 with configurable iterations (default: 300,000)
- **Authentication**: HMAC-SHA256 for encrypted key (with version byte) and ciphertext
- **Extensions**: Supports metadata extensions (e.g., `CREATED_BY`)
- **Minimum footprint**: 140 bytes

### Stream Format v2 (Backward Compatibility - Read Only)
- **Encryption**: AES-256 in CBC mode with custom padding
- **Key Derivation**: SHA-256 iterated 8,192 times with password and IV
- **Authentication**: HMAC-SHA256 for both encrypted key and ciphertext
- **Minimum footprint**: 136 bytes

### Compatibility
✅ **Compatible with**: Official AES Crypt 4.x tools and other v3 implementations  
✅ **Can decrypt**: Stream Format v2 and v3 files  
✅ **Can encrypt**: Stream Format v3 files (with enhanced security)

### Why Stream Format v3?
Stream Format v3 provides significant security improvements over v2:
- **300,000 PBKDF2 iterations** (vs 8,192 SHA-256 iterations) makes brute-force attacks substantially more difficult
- **HMAC includes version byte** to prevent downgrade attacks
- **Standard PKCS#7 padding** improves interoperability

For detailed protocol documentation, see [AES Crypt Stream Format Specification](https://www.aescrypt.com/aes_stream_format.html).

## Projects
- `TronAesCrypt.Core` - Library implementing the AesCrypt v2 (read) and v3 (read/write) stream formats (packaged on build).
- `TronAesCrypt.Main` - Console application (`AesCrypt.exe` / `dotnet AesCrypt.dll`).
- `TronAesCrypt.Core.Tests` & `TronAesCrypt.Main.Tests` - xUnit test projects.

## Encrypting a file

Windows:
```cmd
AesCrypt.exe --encrypt --file ToEncrypted.txt --output ToEncrypted.txt.aes --password Password1234
```
Linux / macOS:
```bash
dotnet AesCrypt.dll --encrypt --file ToEncrypted.txt --output ToEncrypted.txt.aes --password Password1234
```

## Decrypting a file
Windows:
```cmd
AesCrypt.exe --decrypt --file Encrypted.txt.aes --output Encrypted.txt --password Password1234
```
Linux / macOS:
```bash
dotnet AesCrypt.dll --decrypt --file Encrypted.txt.aes --output Encrypted.txt --password Password1234
```

## Library usage
```csharp
var crypter = new AesCrypt();

// Encrypt with v3 format (default: 300,000 PBKDF2 iterations)
crypter.EncryptFile("plain.txt", "plain.txt.aes", "Password1234", 64 * 1024);

// Encrypt with custom iteration count (more secure but slower)
crypter.EncryptFile("plain.txt", "plain.txt.aes", "Password1234", 64 * 1024, kdfIterations: 500_000);

// Decrypt (automatically detects v2 or v3 format)
crypter.DecryptFile("plain.txt.aes", "plain-decrypted.txt", "Password1234", 64 * 1024);
```

## Breaking Changes in Version 2.0

### Stream Format v3 Encryption (Breaking Change)

Starting with version 2.0, **all new encryptions are written in Stream Format v3 format only**. This is a breaking change for workflows that depend on v2-format `.aes` output.

**Impact:**
- ✅ **Decryption**: TronAesCrypt 2.0 can decrypt BOTH v2 and v3 files (full backward compatibility)
- ❌ **Encryption**: TronAesCrypt 2.0 writes ONLY v3 format (not readable by v2-only tools)
- ✅ **API**: Public API remains compatible with 1.x; `kdfIterations` is an optional parameter

**Migration Options:**
1. **Upgrade downstream tools** to support Stream Format v3 (recommended for security)
2. **Stay on TronAesCrypt 1.x** for encryption if you must produce v2-format output
3. **Use official AES Crypt tools** (https://www.aescrypt.com/) which support both v2 and v3

**Why v3?**
- 37x stronger key derivation (300,000 PBKDF2-HMAC-SHA512 iterations vs 8,192 SHA-256)
- Configurable iteration counts for custom security levels
- HMAC includes version byte to prevent downgrade attacks
- Standard PKCS#7 padding

## Performance Note

Stream format v3 uses 300,000 PBKDF2 iterations by default (vs v2's 8,192 SHA-256 iterations). This significantly improves security against brute-force attacks but makes encryption/decryption slower. For high-security scenarios, consider increasing iterations to 500,000 or 1,000,000.

## Build & Test
```bash
dotnet restore
dotnet build -c Release
dotnet test -c Release
```

## Pack
```bash
dotnet pack -c Release TronAesCrypt.Core/TronAesCrypt.Core.csproj
```
Generates a NuGet package with README and LICENSE.

## License
MIT License. See `LICENSE`.
