using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using TRONSoft.TronAesCrypt.Core.Extensions;
using TRONSoft.TronAesCrypt.Core.Helpers;
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

        _ = _aesCryptHeader.ReadHeader(inStream);
        var kdfIterations = GetKdfIterations(inStream);
        var ivMain = inStream.ReadBytes(16);

        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        using var key = new SensitiveData(kdf.DeriveKey(password, ivMain));

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

    /// <inheritdoc />
    public async Task DecryptStreamAsync(Stream inStream, Stream outStream, string password, int bufferSize, CancellationToken cancellationToken = default)
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

        await _aesCryptHeader.ReadHeaderAsync(inStream, cancellationToken).ConfigureAwait(false);
        var kdfIterations = await GetKdfIterationsAsync(inStream, cancellationToken).ConfigureAwait(false);
        var ivMain = await inStream.ReadBytesAsync(16, cancellationToken).ConfigureAwait(false);

        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        using var key = new SensitiveData(kdf.DeriveKey(password, ivMain));

        var mainKeyAndIvRead = await inStream.ReadBytesAsync(48, cancellationToken).ConfigureAwait(false);

        using var hmac1 = new HMACSHA256(key);
        // V3: HMAC with version byte appended
        var dataToHash = new byte[mainKeyAndIvRead.Length + 1];
        Array.Copy(mainKeyAndIvRead, dataToHash, mainKeyAndIvRead.Length);
        dataToHash[mainKeyAndIvRead.Length] = 0x03;
        byte[] hmacMainIvAndKeyActual = hmac1.ComputeHash(dataToHash);

        var hmacMainKeyAndIvRead = await inStream.ReadBytesAsync(32, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(hmacMainKeyAndIvRead, hmacMainIvAndKeyActual))
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }

        await DecryptDataAsync(inStream, outStream, key, ivMain, mainKeyAndIvRead, bufferSize, cancellationToken).ConfigureAwait(false);
    }

    private static void DecryptData(Stream inStream, Stream outStream, byte[] key, byte[] ivMain, byte[] mainKeyAndIv, int bufferSize)
    {
        var (dataIv, internalKey) = DecryptMainKeyAndIv(key, ivMain, mainKeyAndIv);
        using var internalKeyData = new SensitiveData(internalKey);
        using var dataIvData = new SensitiveData(dataIv);
        Decrypt(inStream, outStream, internalKeyData, dataIvData, bufferSize);
    }

    private static async Task DecryptDataAsync(Stream inStream, Stream outStream, byte[] key, byte[] ivMain, byte[] mainKeyAndIv, int bufferSize, CancellationToken cancellationToken)
    {
        var (dataIv, internalKey) = DecryptMainKeyAndIv(key, ivMain, mainKeyAndIv);
        using var internalKeyData = new SensitiveData(internalKey);
        using var dataIvData = new SensitiveData(dataIv);
        await DecryptAsync(inStream, outStream, internalKeyData, dataIvData, bufferSize, cancellationToken).ConfigureAwait(false);
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

        var endPositionEncryptedData = inStream.Length - 32;
        if (endPositionEncryptedData < currentPosition)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }
        var encryptedLength = endPositionEncryptedData - currentPosition;

        // Get hmac
        inStream.Position = endPositionEncryptedData;
        var hmacEncryptedData = inStream.ReadBytes(32);

        // Pass 1: Verify HMAC by reading through ciphertext incrementally
        inStream.Position = currentPosition;
        using (var hmac0 = new HMACSHA256(internalKey))
        {
            hmac0.Initialize();
            var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
            try
            {
                var remaining = encryptedLength;
                while (remaining > 0)
                {
                    var bytesToRead = (int)Math.Min(remaining, bufferSize);
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
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
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
        var decryptBuffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            int bytesReadFromDecrypt;
            while ((bytesReadFromDecrypt = cryptoStream.Read(decryptBuffer, 0, bufferSize)) > 0)
            {
                outStream.Write(decryptBuffer, 0, bytesReadFromDecrypt);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(decryptBuffer, clearArray: true);
        }
    }

    private static async Task DecryptAsync(Stream inStream, Stream outStream, byte[] internalKey, byte[] dataIv, int bufferSize, CancellationToken cancellationToken)
    {
        var currentPosition = inStream.Position;

        var endPositionEncryptedData = inStream.Length - 32;
        if (endPositionEncryptedData < currentPosition)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }
        var encryptedLength = endPositionEncryptedData - currentPosition;

        // Get hmac
        inStream.Position = endPositionEncryptedData;
        var hmacEncryptedData = await inStream.ReadBytesAsync(32, cancellationToken).ConfigureAwait(false);

        // Pass 1: Verify HMAC by reading through ciphertext incrementally
        inStream.Position = currentPosition;
        using (var hmac0 = new HMACSHA256(internalKey))
        {
            hmac0.Initialize();
            var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
            try
            {
                var remaining = encryptedLength;
                while (remaining > 0)
                {
                    var bytesToRead = (int)Math.Min(remaining, bufferSize);
                    var totalBytesRead = 0;
                    while (totalBytesRead < bytesToRead)
                    {
                        var bytesRead = await inStream.ReadAsync(buffer.AsMemory(totalBytesRead, bytesToRead - totalBytesRead), cancellationToken).ConfigureAwait(false);
                        if (bytesRead == 0)
                        {
                            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                        }
                        totalBytesRead += bytesRead;
                    }
                    hmac0.TransformBlock(buffer, 0, totalBytesRead, null, 0);
                    remaining -= totalBytesRead;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
            hmac0.TransformFinalBlock([], 0, 0);
            if (!CryptographicOperations.FixedTimeEquals(hmac0.Hash!, hmacEncryptedData))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }
        }

        // Pass 2: Seek back and decrypt with PKCS#7 padding handling
        inStream.Position = currentPosition;
        await using var limitedStream = new LimitedReadStream(inStream, encryptedLength);
        using var cipher = AesFactory.Create(internalKey, dataIv, usePkcs7Padding: true);
        await using var cryptoStream = new CryptoStream(limitedStream, cipher.CreateDecryptor(), CryptoStreamMode.Read);
        var decryptBuffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            int bytesReadFromDecrypt;
            while ((bytesReadFromDecrypt = await cryptoStream.ReadAsync(decryptBuffer.AsMemory(0, bufferSize), cancellationToken).ConfigureAwait(false)) > 0)
            {
                await outStream.WriteAsync(decryptBuffer.AsMemory(0, bytesReadFromDecrypt), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(decryptBuffer, clearArray: true);
        }
    }

    private int GetKdfIterations(Stream inStream)
    {
        var iterationBytes = inStream.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        var kdfIterations = BitConverter.ToInt32(iterationBytes, 0);
        if (kdfIterations is < MinKdfIterations or > MaxKdfIterations)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }

        return kdfIterations;
    }

    private async Task<int> GetKdfIterationsAsync(Stream inStream, CancellationToken cancellationToken)
    {
        var iterationBytes = await inStream.ReadBytesAsync(4, cancellationToken).ConfigureAwait(false);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        var kdfIterations = BitConverter.ToInt32(iterationBytes, 0);
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

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining <= 0)
            {
                return 0;
            }
            var bytesToRead = (int)Math.Min(buffer.Length, _remaining);
            var bytesRead = await innerStream.ReadAsync(buffer.Slice(0, bytesToRead), cancellationToken).ConfigureAwait(false);
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
