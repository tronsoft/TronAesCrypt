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

        // maximum password length (number of chars)
        private const int MaxPassLen = 1024;

        private readonly AesCryptHeader _aesCryptHeader = new AesCryptHeader();

        public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 16)
        {
            using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputFileName, FileMode.OpenOrCreate, FileAccess.Write);
            EncryptStream(inputStream, outputStream, password, bufferSize);

            inputStream.Close();
            outputStream.Flush();
            outputStream.Close();
        }

        public void DecryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 16)
        {
            using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputFileName, FileMode.OpenOrCreate, FileAccess.Write);
            DecryptStream(inputStream, outputStream, password, bufferSize);

            inputStream.Close();
            outputStream.Flush();
            outputStream.Close();
        }

        /// <summary>
        /// Decrypt the stream
        /// </summary>
        /// <param name="inStream">The input stream.</param>
        /// <param name="outStream">The aes crypt output stream</param>
        /// <param name="password">The password to use for decrypting.</param>
        /// <param name="bufferSize">
        ///     bufferSize: encryption buffer size, must be a multiple of
        ///     AES block size (16)
        ///     using a larger buffer speeds up things when dealing
        ///     with big files
        /// </param>
        /// <returns>The encrypted stream.</returns>
        public void DecryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
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

            // Write header.
            _aesCryptHeader.ReadHeader(inStream);

            // read the iv used to encrypt the main iv and the encryption key
            var ivMain = ReadBytes(inStream, 16);

            var key = StretchPassword(password, ivMain);

            // read encrypted main iv and key
            var mainKeyAndIvRead = ReadBytes(inStream, 48);

            using var hmac1 = new HMACSHA256(key);
            var hmacMainIvAndKeyActual = hmac1.ComputeHash(mainKeyAndIvRead);

            // read HMAC-SHA256 of the encrypted iv and key
            var hmacMainKeyAndIvRead = ReadBytes(inStream, 32);
            if (!hmacMainKeyAndIvRead.SequenceEqual(hmacMainIvAndKeyActual))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

            DecryptData(inStream, outStream, key, ivMain, mainKeyAndIvRead, bufferSize);
        }

        /// <summary>
        /// Encrypt the stream
        /// </summary>
        /// <param name="inStream">The input stream.</param>
        /// <param name="outStream">The aes crypt output stream</param>
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

            var ivData = RandomSaltGenerator.Generate();
            var ivMainKey = RandomSaltGenerator.Generate();
            var key = StretchPassword(password, ivMainKey);

            // create hmac for cipher text
            var internalKey = RandomSaltGenerator.Generate(32);

            // encrypt the main key and iv
            var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);

            _aesCryptHeader.WriteHeader(outStream);

            // write the iv used to encrypt the main iv and the encryption key
            outStream.Write(ivMainKey, 0, ivMainKey.Length);

            // write encrypted main iv and key
            outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);

            // write HMAC-SHA256 of the encrypted iv and key
            using (var hmacMainKeyIv = new HMACSHA256(key))
            {
                var hash = hmacMainKeyIv.ComputeHash(encryptedMainKeyIv);
                outStream.Write(hash, 0, hash.Length);
            }

            // Encrypt the 'real' data.
            var (fileSize, hmac0Value) = EncryptData(inStream, outStream, internalKey, ivData, bufferSize);

            outStream.WriteByte(fileSize);
            outStream.Write(hmac0Value, 0, hmac0Value.Length);

            outStream.Position = 0;
        }

        private static (byte, byte[]) EncryptData(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
        {
            var lastDataReadSize = 0; // File size modulo 16 in least significant byte positions
            using var cipher = CreateAes(internalKey, iv);
            using var ms = new MemoryStream();
            using var cryptoStream = new CryptoStream(ms, cipher.CreateEncryptor(), CryptoStreamMode.Write);
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
                        padding.Fill((byte) padLen);
                        cryptoStream.Write(padding, 0, padding.Length);
                    }
                }
            }

            cryptoStream.FlushFinalBlock();
            ms.Position = 0;

            using var hmac0 = new HMACSHA256(internalKey);
            hmac0.Initialize();

            while ((bytesRead = ms.Read(buffer, 0, buffer.Length)) > 0)
            {
                outStream.Write(buffer, 0, bytesRead);
                hmac0.TransformBlock(buffer, 0, bytesRead, null, 0);
            }

            hmac0.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

            return ((byte) lastDataReadSize, hmac0.Hash);
        }

        private static void DecryptData(Stream inStream, Stream outStream, byte[] key, byte[] ivMain, byte[] mainKeyAndIv, int bufferSize)
        {
            var (dataIv, internalKey) = DecryptMainKeyAndIv(key, ivMain, mainKeyAndIv);
            var currentPosition = inStream.Position;
            var endPositionEncryptedData = inStream.Length - 32 - 1;

            // Get padding and hmac
            inStream.Position = endPositionEncryptedData;
            var padding = (16 - ReadBytes(inStream, 1)[0]) % 16;
            var hmacEncryptedData = ReadBytes(inStream, 32);

            // Reset the position to the beginning of the encrypted data
            inStream.Position = currentPosition;

            // Get hmac
            using var hmac0 = new HMACSHA256(internalKey);
            hmac0.Initialize();

            // Get the cipher
            using var cipher = CreateAes(internalKey, dataIv);
            using var decrypter = cipher.CreateDecryptor();
            // First read as much data as possible.
            ReadEncryptedBytes(bufferSize);

            // read the remaining
            ReadEncryptedBytes();

            // Everything read but the last block need to remove padding
            if (inStream.Position != endPositionEncryptedData)
            {
                var lastBlock = ReadBytes(inStream, AesBlockSize);
                hmac0.TransformBlock(lastBlock, 0, lastBlock.Length, null, 0);

                decrypter.TransformBlock(lastBlock, 0, lastBlock.Length, lastBlock, 0);
                outStream.Write(lastBlock, 0, lastBlock.Length - padding);
            }

            decrypter.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            hmac0.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            if (!hmac0.Hash.SequenceEqual(hmacEncryptedData))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }


            // Functions
            void ReadEncryptedBytes(int bytesToRead = AesBlockSize)
            {
                var buffer = new byte[bytesToRead];
                while (inStream.Position < endPositionEncryptedData - bytesToRead)
                {
                    var bytesRead = inStream.Read(buffer, 0, buffer.Length);
                    hmac0.TransformBlock(buffer, 0, bytesRead, null, 0);
                    decrypter.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                    outStream.Write(buffer, 0, buffer.Length);
                }
            }
        }

        private static RijndaelManaged CreateAes(byte[] key, byte[] iv) => new RijndaelManaged()
        {
            KeySize = KeySize * 8,
            BlockSize = AesBlockSize * 8,
            Padding = PaddingMode.None,
            Mode = CipherMode.CBC,
            Key = key,
            IV = iv
        };

        private static byte[] EncryptMainKeyAndIv(byte[] key, byte[] iv, byte[] internalKey, byte[] ivInternal)
        {
            using var cipher = CreateAes(key, iv);
            using var msEncrypt = new MemoryStream();
            using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(ivInternal, 0, ivInternal.Length);
            cryptoStream.Write(internalKey, 0, internalKey.Length);
            cryptoStream.FlushFinalBlock();
            cryptoStream.Close();

            return msEncrypt.ToArray();
        }

        private static (byte[], byte[]) DecryptMainKeyAndIv(byte[] key, byte[] iv, byte[] encryptedMainKeyIv)
        {
            using var cipher = CreateAes(key, iv);
            using var msEncrypt = new MemoryStream(encryptedMainKeyIv);
            using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateDecryptor(), CryptoStreamMode.Read);
            var ivInternal = new byte[16];
            cryptoStream.Read(ivInternal, 0, ivInternal.Length);

            var internalKey = new byte[32];
            cryptoStream.Read(internalKey, 0, internalKey.Length);
            cryptoStream.Close();

            return (ivInternal, internalKey);
        }

        private static byte[] StretchPassword(string password, byte[] iv)
        {
            var passwordBytes = password.GetUtf16Bytes();
            using var hash = SHA256.Create();
            var key = new byte[KeySize];
            Array.Copy(iv, key, iv.Length);

            for (var i = 0; i < 8192; i++)
            {
                hash.Initialize();
                hash.TransformBlock(key, 0, key.Length, key, 0);
                hash.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
                key = hash.Hash;
            }

            return key;
        }

        private static byte[] ReadBytes(Stream stream, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            var bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead != bufferSize)
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

            return buffer;
        }
    }
}