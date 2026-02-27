using System;
using System.IO;
using System.Security.Cryptography;
using TRONSoft.TronAesCrypt.Core.Helpers;
using TRONSoft.TronAesCrypt.Core.KeyDerivation;
using TRONSoft.TronAesCrypt.Core.Streams;

namespace TRONSoft.TronAesCrypt.Core.Encryptors;

internal class AesV3Encryptor :IAesEncryptor
{
    private const int MinKdfIterations = 10_000;
    private const int MaxKdfIterations = 10_000_000;
    private const int AesBlockSize = 16;
    private const int MaxPassLen = 1024;

    private readonly AesCryptHeader _aesCryptHeader = new();

    /// <inheritdoc />
    public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000)
    {
        ArgumentNullException.ThrowIfNull(inStream);
        ArgumentNullException.ThrowIfNull(outStream);
        ArgumentNullException.ThrowIfNull(password);

        if (bufferSize % AesBlockSize != 0)
        {
            throw new ArgumentException("Buffer size must be a multiple of AES block size.");
        }

        if (password.Length > MaxPassLen)
        {
            throw new ArgumentException("The password is too long.");
        }

        if (kdfIterations < MinKdfIterations || kdfIterations > MaxKdfIterations)
        {
            throw new ArgumentOutOfRangeException(
                nameof(kdfIterations),
                @$"KDF iterations must be between {MinKdfIterations} and {MaxKdfIterations}");
        }

        var ivData = RandomSaltGenerator.Generate();
        var ivMainKey = RandomSaltGenerator.Generate();

        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        var key = kdf.DeriveKey(password, ivMainKey);
        var internalKey = RandomSaltGenerator.Generate(32);
        try
        {
            var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);

            _aesCryptHeader.WriteHeaderV3(outStream, kdfIterations);
            outStream.Write(ivMainKey, 0, ivMainKey.Length);
            outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);

            using (var hmacMainKeyIv = new HMACSHA256(key))
            {
                var dataToHash = new byte[encryptedMainKeyIv.Length + 1];
                Array.Copy(encryptedMainKeyIv, dataToHash, encryptedMainKeyIv.Length);
                dataToHash[encryptedMainKeyIv.Length] = 0x03;
                var hash = hmacMainKeyIv.ComputeHash(dataToHash);
                outStream.Write(hash, 0, hash.Length);
            }

            var hmac0Value = EncryptDataV3(inStream, outStream, internalKey, ivData, bufferSize);

            // V3: No modulo byte, just the HMAC
            outStream.Write(hmac0Value, 0, hmac0Value.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(internalKey);
        }
    }

    private static byte[] EncryptMainKeyAndIv(byte[] key, byte[] iv, byte[] internalKey, byte[] ivInternal)
    {
        using var cipher = AesFactory.Create(key, iv);
        using var msEncrypt = new MemoryStream();
        using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(ivInternal, 0, ivInternal.Length);
        cryptoStream.Write(internalKey, 0, internalKey.Length);
        cryptoStream.FlushFinalBlock();

        return msEncrypt.ToArray();
    }

    private static byte[] EncryptDataV3(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
    {
        using var cipher = AesFactory.Create(internalKey, iv, usePkcs7Padding: true);
        using var hmac0 = new HMACSHA256(internalKey);
        hmac0.Initialize();

        using var hmacStream = new HmacComputingStream(outStream, hmac0);
        using var cryptoStream = new CryptoStream(hmacStream, cipher.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true);
        int bytesRead;
        var buffer = new byte[bufferSize];
        while ((bytesRead = inStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, bytesRead);
        }

        cryptoStream.FlushFinalBlock();

        return hmacStream.GetHmacHash();
    }
}
