using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

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

    private readonly AesCryptHeader _aesCryptHeader = new();

    public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 16, int kdfIterations = 300_000)
    {
        using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFileName, FileMode.OpenOrCreate, FileAccess.Write);
        EncryptStream(inputStream, outputStream, password, bufferSize, kdfIterations);

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
    /// Decrypt the stream. Automatically detects and supports both v2 and v3 stream formats.
    /// </summary>
    /// <param name="inStream">The input stream.</param>
    /// <param name="outStream">The output stream for decrypted data</param>
    /// <param name="password">The password to use for decrypting.</param>
    /// <param name="bufferSize">
    ///     bufferSize: decryption buffer size, must be a multiple of
    ///     AES block size (16)
    ///     using a larger buffer speeds up things when dealing
    ///     with big files
    /// </param>
    /// <exception cref="InvalidOperationException">
    ///     Thrown when the file is corrupt, the password is incorrect, or the stream format is unsupported.
    /// </exception>
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

        // Read header and detect version
        var version = _aesCryptHeader.ReadHeader(inStream);

        // Read KDF iteration count for v3
        int kdfIterations = 0;
        if (version == AesCryptVersion.V3)
        {
            var iterationBytes = ReadBytes(inStream, 4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(iterationBytes);
            }
            kdfIterations = BitConverter.ToInt32(iterationBytes, 0);
        }

        // read the iv used to encrypt the main iv and the encryption key
        var ivMain = ReadBytes(inStream, 16);

        // Derive key based on version
        byte[] key;
        if (version == AesCryptVersion.V2)
        {
            var kdf = new Sha256IterativeKeyDerivation();
            key = kdf.DeriveKey(password, ivMain);
        }
        else // V3
        {
            var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
            key = kdf.DeriveKey(password, ivMain);
        }

        // read encrypted main iv and key
        var mainKeyAndIvRead = ReadBytes(inStream, 48);

        using var hmac1 = new HMACSHA256(key);
        byte[] hmacMainIvAndKeyActual;

        if (version == AesCryptVersion.V2)
        {
            // V2: HMAC without version byte
            hmacMainIvAndKeyActual = hmac1.ComputeHash(mainKeyAndIvRead);
        }
        else // V3
        {
            // V3: HMAC with version byte appended
            var dataToHash = new byte[mainKeyAndIvRead.Length + 1];
            Array.Copy(mainKeyAndIvRead, dataToHash, mainKeyAndIvRead.Length);
            dataToHash[mainKeyAndIvRead.Length] = 0x03;
            hmacMainIvAndKeyActual = hmac1.ComputeHash(dataToHash);
        }

        // read HMAC-SHA256 of the encrypted iv and key
        var hmacMainKeyAndIvRead = ReadBytes(inStream, 32);
        if (!hmacMainKeyAndIvRead.SequenceEqual(hmacMainIvAndKeyActual))
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }

        DecryptData(inStream, outStream, key, ivMain, mainKeyAndIvRead, bufferSize, version);
    }

    /// <summary>
    /// Encrypt the stream using AES Crypt v3 format with PBKDF2-HMAC-SHA512 key derivation.
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
    /// <param name="kdfIterations">
    ///     The number of PBKDF2-HMAC-SHA512 iterations for key derivation (default: 300,000).
    ///     Higher values provide better security against brute-force attacks but increase processing time.
    /// </param>
    /// <returns>The encrypted stream.</returns>
    public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000)
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

        // Use PBKDF2-HMAC-SHA512 for v3
        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        var key = kdf.DeriveKey(password, ivMainKey);

        // create hmac for cipher text
        var internalKey = RandomSaltGenerator.Generate(32);

        // encrypt the main key and iv
        var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);

        // Write v3 header with KDF iteration count
        _aesCryptHeader.WriteHeaderV3(outStream, kdfIterations);

        // write the iv used to encrypt the main iv and the encryption key
        outStream.Write(ivMainKey, 0, ivMainKey.Length);

        // write encrypted main iv and key
        outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);

        // write HMAC-SHA256 of the encrypted iv and key (with version byte 0x03 appended)
        using (var hmacMainKeyIv = new HMACSHA256(key))
        {
            var dataToHash = new byte[encryptedMainKeyIv.Length + 1];
            Array.Copy(encryptedMainKeyIv, dataToHash, encryptedMainKeyIv.Length);
            dataToHash[encryptedMainKeyIv.Length] = 0x03; // Append version byte
            var hash = hmacMainKeyIv.ComputeHash(dataToHash);
            outStream.Write(hash, 0, hash.Length);
        }

        // Encrypt the 'real' data using PKCS#7 padding
        var hmac0Value = EncryptDataV3(inStream, outStream, internalKey, ivData, bufferSize);

        // V3: No modulo byte, just the HMAC
        outStream.Write(hmac0Value, 0, hmac0Value.Length);

        outStream.Position = 0;
    }

    private static (byte, byte[]) EncryptData(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
    {
        var lastDataReadSize = 0; // File size modulo 16 in the least significant byte positions
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

        hmac0.TransformFinalBlock([], 0, 0);

        return ((byte) lastDataReadSize, hmac0.Hash);
    }

    private static byte[] EncryptDataV3(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
    {
        // Use PKCS#7 padding for v3
        using var cipher = CreateAes(internalKey, iv, usePkcs7Padding: true);
        using var ms = new MemoryStream();
        using var cryptoStream = new CryptoStream(ms, cipher.CreateEncryptor(), CryptoStreamMode.Write);
        
        int bytesRead;
        var buffer = new byte[bufferSize];
        while ((bytesRead = inStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, bytesRead);
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

        hmac0.TransformFinalBlock([], 0, 0);

        return hmac0.Hash!;
    }

    private static void DecryptData(Stream inStream, Stream outStream, byte[] key, byte[] ivMain, byte[] mainKeyAndIv, int bufferSize, AesCryptVersion version)
    {
        var (dataIv, internalKey) = DecryptMainKeyAndIv(key, ivMain, mainKeyAndIv);
        var currentPosition = inStream.Position;

        if (version == AesCryptVersion.V2)
        {
            // V2: Has modulo byte before final HMAC
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
            using var cipher = CreateAes(internalKey, dataIv, usePkcs7Padding: false);
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

            decrypter.TransformFinalBlock([], 0, 0);
            hmac0.TransformFinalBlock([], 0, 0);
            if (!hmac0.Hash!.SequenceEqual(hmacEncryptedData))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

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
        else // V3
        {
            // V3: No modulo byte, just HMAC at the end, and uses PKCS#7 padding
            var endPositionEncryptedData = inStream.Length - 32;

            // Get hmac
            inStream.Position = endPositionEncryptedData;
            var hmacEncryptedData = ReadBytes(inStream, 32);

            // Reset the position to the beginning of the encrypted data
            inStream.Position = currentPosition;

            using var hmac0 = new HMACSHA256(internalKey);
            hmac0.Initialize();

            // Read all encrypted data into memory for HMAC verification, then decrypt
            using var encryptedDataStream = new MemoryStream();
            var buffer = new byte[bufferSize];
            int bytesRead;

            while (inStream.Position < endPositionEncryptedData)
            {
                var bytesToRead = (int)Math.Min(bufferSize, endPositionEncryptedData - inStream.Position);
                bytesRead = inStream.Read(buffer, 0, bytesToRead);
                hmac0.TransformBlock(buffer, 0, bytesRead, null, 0);
                encryptedDataStream.Write(buffer, 0, bytesRead);
            }

            hmac0.TransformFinalBlock([], 0, 0);
            if (!hmac0.Hash!.SequenceEqual(hmacEncryptedData))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

            // Now decrypt with PKCS#7 padding handling
            encryptedDataStream.Position = 0;
            using var cipher = CreateAes(internalKey, dataIv, usePkcs7Padding: true);
            using var cryptoStream = new CryptoStream(encryptedDataStream, cipher.CreateDecryptor(), CryptoStreamMode.Read);

            while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                outStream.Write(buffer, 0, bytesRead);
            }
        }
    }

    private static Aes CreateAes(byte[] key, byte[] iv, bool usePkcs7Padding = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        if (key.Length != KeySize)
        {
            throw new ArgumentException($@"Key length must be {KeySize} bytes for AES-256.", nameof(key));
        }
        if (iv.Length != AesBlockSize)
        {
            throw new ArgumentException($@"IV length must be {AesBlockSize} bytes.", nameof(iv));
        }

        var aes = Aes.Create();
        aes.KeySize = KeySize * 8;
        aes.BlockSize = AesBlockSize * 8;
        aes.Padding = usePkcs7Padding ? PaddingMode.PKCS7 : PaddingMode.None;
        aes.Mode = CipherMode.CBC;
        aes.Key = key;
        aes.IV = iv;
        return aes;
    }

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
        cryptoStream.ReadExactly(ivInternal, 0, ivInternal.Length);

        var internalKey = new byte[32];
        cryptoStream.ReadExactly(internalKey, 0, internalKey.Length);
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
            hash.TransformBlock(key!, 0, key!.Length, key, 0);
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