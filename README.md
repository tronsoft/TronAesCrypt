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

## Migration from v2

If you have files encrypted with the previous version (1.x) using stream format v2:
- **Decryption**: Works seamlessly - the library automatically detects and decrypts v2 files
- **Re-encryption**: To upgrade to v3 format, simply decrypt and re-encrypt files with version 2.0+
- **No Breaking Changes**: The API remains compatible; `kdfIterations` is an optional parameter

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
