# TronAesCrypt
An implementation of [AesCrypt](https://www.aescrypt.com/) in C#. It support version 2 of the AesCrypt 
file format. The file format is describe [here](https://www.aescrypt.com/aes_file_format.html).

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
