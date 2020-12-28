using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core
{
    public class AesCrypt
    {
        // AES block size in bytes
        public const int AesBlockSize = 16;

        /// <summary>
        ///     The size of the key. For AES-256 that is 256/8 = 32
        /// </summary>
        public const int KeySize = 32;

        // encryption/decryption buffer size - 64K
        public const int BufferSize = 64 * 1024;

        // maximum password length (number of chars)
        public const int MaxPassLen = 1024;

        private static readonly byte[] AesHeader = "AES".GetUtf8Bytes();

        public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize)
        {
            using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputFileName, FileMode.Open, FileAccess.Write);
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

            var passwordBytes = password.GetUtf8Bytes();
            var ivData = GenerateRandomSalt();
            var ivMainKey = GenerateRandomSalt();

            // create hmac for cipher text
            var internalKey = GenerateRandomSalt(32);
            using var hmac0 = new HMACSHA256(internalKey);
            var hmac0Value = hmac0.ComputeHash(inStream);
            inStream.Position = 0;

            // encrypt the main key and iv
            var encryptedMainKeyIv = EncryptMainKeyAndIV(passwordBytes, ivMainKey);

            WriteHeader(outStream);

            // write the iv used to encrypt the main iv and the encryption key
            outStream.Write(ivMainKey);

            // write encrypted main iv and key
            outStream.Write(encryptedMainKeyIv);

            // write HMAC-SHA256 of the encrypted iv and key
            using var hmac1 = new HMACSHA256(passwordBytes);
            outStream.Write(hmac1.ComputeHash(encryptedMainKeyIv));

            // Encrypt the 'real' data.
            var fileSize = EncryptData(inStream, outStream, internalKey, ivData);
            outStream.WriteByte(fileSize);
            outStream.Write(hmac0Value);
            outStream.Position = 0;
        }

        private static byte EncryptData(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv)
        {
            using var cipher = CreateAes(internalKey, iv);
            using var cryptoStream = new CryptoStream(outStream, cipher.CreateEncryptor(), CryptoStreamMode.Write, true);
            var totalBytesRead = 0;
            int bytesRead;
            var buffer = new byte[1024];
            do
            {
                bytesRead = inStream.Read(buffer, 0, buffer.Length);
                totalBytesRead += bytesRead;
                cryptoStream.Write(buffer, 0, bytesRead);
            } while (bytesRead > 0);

            cryptoStream.Close();

            return (byte) (totalBytesRead % AesBlockSize);
        }

        private static RijndaelManaged CreateAes(string password, byte[] iv)
        {
            return CreateAes(password.GetUtf8Bytes(), iv);
        }

        private static RijndaelManaged CreateAes(byte[] password, byte[] iv)
        {
            var key = CreateKey(password, iv);
            return new RijndaelManaged
            {
                KeySize = KeySize * 8,
                BlockSize = AesBlockSize * 8,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = key.GetBytes(KeySize),
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
            var appName = "TronAesCrypt";

            // Write CREATED_BY extension length
            outStream.WriteByte(0);
            outStream.WriteByte((byte) ((createdBy + appName).Length + 1));

            // Write the CREATED_BY extension
            outStream.Write(createdBy.GetUtf8Bytes());
            outStream.WriteByte(0);
            outStream.Write(appName.GetUtf8Bytes());

            // Write extensions container
            outStream.WriteByte(0);
            outStream.WriteByte(80);

            outStream.Write(new byte[128]);

            // write end-of-extensions tag
            outStream.WriteByte(0);
            outStream.WriteByte(0);
        }

        private static Rfc2898DeriveBytes CreateKey(string password, byte[] iv)
        {
            return CreateKey(password.GetUtf8Bytes(), iv);
        }

        private static Rfc2898DeriveBytes CreateKey(byte[] password, byte[] iv)
        {
            return new(password, iv, 50000);
        }

        private byte[] EncryptMainKeyAndIV(byte[] password, byte[] iv)
        {
            using var cipher = CreateAes(password, iv);
            using var msEncrypt = new MemoryStream();
            using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(iv);
            cryptoStream.Write(password);
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
    }
}