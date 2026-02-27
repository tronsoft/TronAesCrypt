using System;
using System.IO;
using System.Security.Cryptography;
using TRONSoft.TronAesCrypt.Core.Extensions;
using TRONSoft.TronAesCrypt.Core.KeyDerivation;

namespace TRONSoft.TronAesCrypt.Core.Decryptors;

/// <summary>
/// Decrypts AES Crypt stream format v3 ciphertext.
/// V3 uses standard PKCS#7 padding and no modulo byte; HMAC-SHA256 is the last 32 bytes of the stream.
/// A two-pass approach is used: Pass 1 verifies the HMAC, Pass 2 decrypts the ciphertext.
/// </summary>
internal sealed class AesV3Decryptor : IAesDecryptor
{
    private const int AesBlockSize = 16;
    private const int MaxPassLen = 1024;
    private const int MinKdfIterations = 10_000;
    private const int MaxKdfIterations = 10_000_000;

    private readonly AesCryptHeader _aesCryptHeader = new();

    /// <inheritdoc />
    public void DecryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
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

        if (!inStream.CanSeek)
        {
            throw new ArgumentException(
                @"Input stream must be seekable for decryption (v2/v3 format requires reading file header and trailer).",
                nameof(inStream));
        }

        var version = _aesCryptHeader.ReadHeader(inStream);
        var kdfIterations = GetkdfIterations(inStream);
        var ivMain = inStream.ReadBytes(16);

        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        var key = kdf.DeriveKey(password, ivMain);
        try
        {
            var mainKeyAndIvRead = inStream.ReadBytes(48);

            using var hmac1 = new HMACSHA256(key);
            // V3: HMAC with version byte appended
            var dataToHash = new byte[mainKeyAndIvRead.Length + 1];
            Array.Copy(mainKeyAndIvRead, dataToHash, mainKeyAndIvRead.Length);
            dataToHash[mainKeyAndIvRead.Length] = 0x03;
            byte[] hmacMainIvAndKeyActual = hmac1.ComputeHash(dataToHash);

            var hmacMainKeyAndIvRead = inStream.ReadBytes(32);
            if (!CryptographicOperations.FixedTimeEquals(hmacMainKeyAndIvRead, hmacMainIvAndKeyActual))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

            DecryptData(inStream, outStream, key, ivMain, mainKeyAndIvRead, bufferSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void DecryptData(Stream inStream, Stream outStream, byte[] key, byte[] ivMain, byte[] mainKeyAndIv, int bufferSize)
    {
        var (dataIv, internalKey) = DecryptMainKeyAndIv(key, ivMain, mainKeyAndIv);
        try
        {
            Decrypt(inStream, outStream, internalKey, dataIv, bufferSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(internalKey);
            CryptographicOperations.ZeroMemory(dataIv);
        }
    }

    private static (byte[], byte[]) DecryptMainKeyAndIv(byte[] key, byte[] iv, byte[] encryptedMainKeyIv)
    {
        using var cipher = AesFactory.Create(key, iv);
        using var msEncrypt = new MemoryStream(encryptedMainKeyIv);
        using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateDecryptor(), CryptoStreamMode.Read);
        var ivInternal = new byte[16];
        cryptoStream.ReadExactly(ivInternal, 0, ivInternal.Length);

        var internalKey = new byte[32];
        cryptoStream.ReadExactly(internalKey, 0, internalKey.Length);

        return (ivInternal, internalKey);
    }

    private static void Decrypt(Stream inStream, Stream outStream, byte[] internalKey, byte[] dataIv, int bufferSize)
    {
        var currentPosition = inStream.Position;

        // No modulo byte, just HMAC at the end, and uses PKCS#7 padding
        var endPositionEncryptedData = inStream.Length - 32;
        var encryptedLength = endPositionEncryptedData - currentPosition;

        // Get hmac
        inStream.Position = endPositionEncryptedData;
        var hmacEncryptedData = inStream.ReadBytes(32);

        // Pass 1: Verify HMAC by reading through ciphertext incrementally
        inStream.Position = currentPosition;
        using (var hmac0 = new HMACSHA256(internalKey))
        {
            hmac0.Initialize();
            var buffer = new byte[bufferSize];
            var remaining = encryptedLength;
            while (remaining > 0)
            {
                var bytesToRead = (int)Math.Min(remaining, buffer.Length);
                var totalBytesRead = 0;
                while (totalBytesRead < bytesToRead)
                {
                    var bytesRead = inStream.Read(buffer, totalBytesRead, bytesToRead - totalBytesRead);
                    if (bytesRead == 0)
                    {
                        throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                    }
                    totalBytesRead += bytesRead;
                }
                hmac0.TransformBlock(buffer, 0, totalBytesRead, null, 0);
                remaining -= totalBytesRead;
            }
            hmac0.TransformFinalBlock([], 0, 0);
            if (!CryptographicOperations.FixedTimeEquals(hmac0.Hash!, hmacEncryptedData))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }
        }

        // Pass 2: Seek back and decrypt with PKCS#7 padding handling
        inStream.Position = currentPosition;
        using var limitedStream = new LimitedReadStream(inStream, encryptedLength);
        using var cipher = AesFactory.Create(internalKey, dataIv, usePkcs7Padding: true);
        using var cryptoStream = new CryptoStream(limitedStream, cipher.CreateDecryptor(), CryptoStreamMode.Read);
        var decryptBuffer = new byte[bufferSize];
        int bytesReadFromDecrypt;
        while ((bytesReadFromDecrypt = cryptoStream.Read(decryptBuffer, 0, decryptBuffer.Length)) > 0)
        {
            outStream.Write(decryptBuffer, 0, bytesReadFromDecrypt);
        }
    }

    private int GetkdfIterations(Stream inStream)
    {
        var kdfIterations = 0;
        var iterationBytes = inStream.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        kdfIterations = BitConverter.ToInt32(iterationBytes, 0);
        if (kdfIterations is < MinKdfIterations or > MaxKdfIterations)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }

        return kdfIterations;
    }

    private sealed class LimitedReadStream(Stream innerStream, long maxBytes) : Stream
    {
        private long _remaining = maxBytes;

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0)
            {
                return 0;
            }
            var bytesToRead = (int)Math.Min(count, _remaining);
            var bytesRead = innerStream.Read(buffer, offset, bytesToRead);
            _remaining -= bytesRead;
            return bytesRead;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
