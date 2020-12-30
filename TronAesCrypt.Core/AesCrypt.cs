using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core
{
    public class AesCrypt
    {
        // AES block size in bytes
        private const int AesBlockSize = 16;

        /// <summary>
        ///     The size of the key. For AES-256 that is 256/8 = 32
        /// </summary>
        private const int KeySize = 32;

        // encryption/decryption buffer size - 64K
        public const int BufferSize = 64 * 1024;
        public const string Version = "0.1.0";
        public const string AppName = "TronAesCrypt";

        // maximum password length (number of chars)
        private const int MaxPassLen = 1024;

        private static readonly byte[] AesHeader = "AES".GetUtf8Bytes();

        public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize)
        {
            using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputFileName, FileMode.OpenOrCreate, FileAccess.Write);
            EncryptStream(inputStream, outputStream, password, bufferSize);

            inputStream.Close();
            outputStream.Flush();
            outputStream.Close();
        }

        public FileStream Decrypt(string encryptedFileName, string decryptedFileName, string password)
        {
            using var encryptedFile = new FileStream(encryptedFileName, FileMode.Open);

            // read the salt
            var salt = new byte[32];
            encryptedFile.Read(salt, 0, salt.Length);

            using var aes = CreateAes(password, salt);
            using var cryptoStream = new CryptoStream(encryptedFile, aes.CreateDecryptor(), CryptoStreamMode.Read);
            var decryptedFile = new FileStream(decryptedFileName, FileMode.Create);

            int read;
            var buffer = new byte[1024 * 1024];
            while ((read = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                decryptedFile.Write(buffer, 0, read);
            }

            cryptoStream.Close();

            return decryptedFile;
        }

        /// <summary>
        /// </summary>
        /// <param name="inStream">The input stream.</param>
        /// <param name="outStream">The aescrypt output stream</param>
        /// <param name="password">The password to use for encrypting.</param>
        /// <param name="bufferSize">
        ///     bufferSize: encryption buffer size, must be a multiple of
        ///     AES block size (16)
        ///     using a larger buffer speeds up things when dealing
        ///     with big files
        /// </param>
        /// <returns>The encrypted stream.</returns>
        public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
        {
            // Validate the buffer size 
            if (bufferSize % AesBlockSize != 0)
            {
                throw new ArgumentException("Buffer size must be a multiple of AES block size.");
            }

            // Validate password  length
            if (password.Length > MaxPassLen)
            {
                throw new ArgumentException("The password is too long.");
            }

            var iv0Data = GenerateRandomSalt();
            var iv1MainKey = GenerateRandomSalt();
            var key = StretchPassword(password, iv1MainKey);

            // create hmac for cipher text
            var internalKey = GenerateRandomSalt(32);
            
            // encrypt the main key and iv
            var encryptedMainKeyIv = EncryptMainKeyAndIV(key, iv1MainKey, internalKey, iv0Data);

            WriteHeader(outStream);

            // write the iv used to encrypt the main iv and the encryption key
            outStream.Write(iv1MainKey);

            // write encrypted main iv and key
            outStream.Write(encryptedMainKeyIv);

            // write HMAC-SHA256 of the encrypted iv and key
            using var hmac1 = new HMACSHA256(key);
            outStream.Write(hmac1.ComputeHash(encryptedMainKeyIv));

            // Encrypt the 'real' data.
            var (fileSize, hmac0Value) = EncryptData(inStream, outStream, internalKey, iv0Data, bufferSize);
            
            outStream.WriteByte(fileSize);
            outStream.Write(hmac0Value);
            
            outStream.Position = 0;
        }

        private static (byte, byte[]) EncryptData(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
        {
           var lastDataReadSize = 0; // File size modulo 16 in least significant bit positions
            using var cipher = CreateAes(internalKey, iv);
            using var ms = new MemoryStream();
            using var cryptoStream = new CryptoStream(ms, cipher.CreateEncryptor(), CryptoStreamMode.Write, true);
            int bytesRead;
            var buffer = new byte[bufferSize];
            while ((bytesRead = inStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cryptoStream.Write(buffer, 0, bytesRead);
                if (bytesRead < bufferSize)
                {
                    lastDataReadSize = bytesRead % AesBlockSize;
                    if (lastDataReadSize != 0)
                    {
                        var padLen = 16 - bytesRead % AesBlockSize;
                        var padding = new byte[padLen];
                        Array.Fill(padding, (byte)padLen);
                        cryptoStream.Write(padding);
                    }
                }
            }

            cryptoStream.FlushFinalBlock();
            cryptoStream.Close();
            ms.Position = 0;
            
            using var hmac0 = new HMACSHA256(internalKey);
            hmac0.Initialize();
            
            while ((bytesRead = ms.Read(buffer, 0, buffer.Length)) > 0)
            {
                outStream.Write(buffer, 0, bytesRead);
                hmac0.TransformBlock(buffer, 0, bytesRead, null, 0);
            }

            hmac0.TransformFinalBlock(new byte[0], 0, 0);

            return ((byte) lastDataReadSize, hmac0.Hash);
        }

        private static RijndaelManaged CreateAes(string password, byte[] iv)
        {
            return CreateAes(password.GetUtf8Bytes(), iv);
        }

        private static RijndaelManaged CreateAes(byte[] key, byte[] iv)
        {
            return new RijndaelManaged
            {
                KeySize = KeySize * 8,
                BlockSize = AesBlockSize * 8,
                Padding = PaddingMode.None, //.PKCS7, // of moet dit none zijn?
                Mode = CipherMode.CBC,
                Key = key,
                IV = iv
            };
        }

        private static void WriteHeader(Stream outStream)
        {
            // Write header.
            outStream.Write(AesHeader);

            // write version (AES Crypt version 2 file format -
            // see https://www.aescrypt.com/aes_file_format.html)
            outStream.WriteByte(2);

            // reserved byte (set to zero)
            outStream.WriteByte(0);

            WriteExtensions(outStream);
        }

        private static void WriteExtensions(Stream outStream)
        {
            // Created-by extensions
            var createdBy = "CREATED_BY";
            var appName = $"{AppName} {Version}";

            // Write CREATED_BY extension length
            outStream.WriteByte(0);
            outStream.WriteByte((byte) ((createdBy + appName).Length + 1));

            // Write the CREATED_BY extension
            outStream.Write(createdBy.GetUtf8Bytes());
            outStream.WriteByte(0);
            outStream.Write(appName.GetUtf8Bytes());

            // Write extensions container
            outStream.WriteByte(0);
            outStream.WriteByte(128);

            outStream.Write(new byte[128]);

            // write end-of-extensions tag
            outStream.WriteByte(0);
            outStream.WriteByte(0);
        }

        private byte[] EncryptMainKeyAndIV(byte[] key, byte[] iv, byte[] internalKey, byte[] ivInternal)
        {
            using var cipher = CreateAes(key, iv);
            using var msEncrypt = new MemoryStream();
            using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(ivInternal);
            cryptoStream.Write(internalKey);
            cryptoStream.FlushFinalBlock();

            return msEncrypt.ToArray();
        }

        /// <summary>
        ///     Creates a random salt that will be used to encrypt your file. This method is required on FileEncrypt.
        /// </summary>
        /// <returns></returns>
        private static byte[] GenerateRandomSalt(int size = AesBlockSize)
        {
             if (size < 1)
             {
                 throw new ArgumentException("Size must be greater or equal to 1");
             }
            
             var data = new byte[size];
             using var rng = new RNGCryptoServiceProvider();
             rng.GetBytes(data);
             
             return data;
        }
        
        private byte[] StretchPassword(string password, byte[] iv)
        {
            var passwordBytes = password.GetUtf16Bytes();
            using var hash = SHA256.Create();
            var key = new byte[KeySize];
            Array.Copy(iv, key, iv.Length);
            
            for (var i = 0; i < 8192; i++)
            {
                hash.Initialize();
                hash.TransformBlock(key!, 0, key.Length, key, 0);
                hash.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
                key = hash.Hash;
            }
            
            return key;
        }
    }
}
