# TronAesCrypt
An implementation of [AesCrypt](https://www.aescrypt.com/) in C#. It support version 2 of the AesCrypt 
file format. The file format is describe [here](https://www.aescrypt.com/aes_file_format.html).

# Running tests
**Only on Windows:** The **CheckEncryptionFile** test uses AesCrypt to check the results. To run the test AesCrypt must be in the path environment variable
for the tests to work. AesCrypt on Windows system is usually installed in *C:\Program Files\AESCrypt*. The test is currently ignored.
