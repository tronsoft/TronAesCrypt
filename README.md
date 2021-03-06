# TronAesCrypt
An implementation of [AesCrypt](https://www.aescrypt.com/) in C#. It support version 2 of the AesCrypt 
file format. The file format is describe [here](https://www.aescrypt.com/aes_file_format.html).

# Run the commandline tool
Encrypting a file.

On Windows:
  ```cmd
  AesCrypt.exe --encrypt --file ToEncrypted.txt --output ToEncrypted.txt.aes --password Password1234
  ```

On Linux/MacOs
  ```bash
  dotnet AesCrypt.dll --encrypt --file ToEncrypted.txt --output ToEncrypted.txt.aes --password Password1234
  ```

Decrypting a file.

  ```cmd
  AesCrypt.exe --decrypt --file Encrypted.txt.aes --output Encrypted.txt --password Password1234
  ```

On Linux/MacOs
  ```bash
  dotnet AesCrypt.dll --decrypt --file Encrypted.txt.aes --output Encrypted.txt --password Password1234
  ```
