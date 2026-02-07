# TronAesCrypt
An implementation of [AesCrypt](https://www.aescrypt.com/) in C#. It supports version 2 of the AesCrypt 
file format. The file format is described [here](https://www.aescrypt.com/aes_file_format.html).

## Protocol & Compatibility

This library implements **AES Crypt Stream Format v2** for encrypting and decrypting `.aes` files.

### Stream Format v2
- **Encryption**: AES-256 in CBC mode
- **Key Derivation**: SHA-256 iterated 8,192 times with password and IV
- **Authentication**: HMAC-SHA256 for both encrypted key and ciphertext
- **Extensions**: Supports metadata extensions (e.g., `CREATED_BY`)
- **Minimum footprint**: 136 bytes

### Compatibility
✅ **Compatible with**: Official AES Crypt tools and other v2 implementations  
✅ **Can decrypt**: Stream Format v2 files  
❌ **Cannot decrypt**: Stream Format v3 files (newer format)

### About Stream Format v3
The official AES Crypt specification now includes **Stream Format v3** with enhanced security:
- **Stronger KDF**: PBKDF2-HMAC-SHA512 with configurable iteration count (vs v2's fixed 8,192 SHA-256 iterations)
- **Improved HMAC**: Includes version byte in authentication
- **Standard padding**: PKCS#7 (vs v2's modulo byte)

**Note**: This implementation uses v2 for broad compatibility. Stream Format v3 provides stronger resistance to brute-force password attacks and may be supported in a future version.

For detailed protocol documentation, see [AES Crypt File Format Specification](https://www.aescrypt.com/aes_file_format.html).

## Projects
- `TronAesCrypt.Core` - Library implementing the AesCrypt v2 file format (packaged on build).
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
crypter.EncryptFile("plain.txt", "plain.txt.aes", "Password1234", 64 * 1024);
crypter.DecryptFile("plain.txt.aes", "plain-decrypted.txt", "Password1234", 64 * 1024);
```

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
