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
/// Decrypts AES Crypt stream format v2 ciphertext.
/// V2 uses a modulo byte (plaintext_size % 16) before the final HMAC-SHA256.
/// </summary>
internal sealed class AesV2Decryptor : IAesDecryptor
{
    private const int AesBlockSize = 16;
    private const int MaxPassLen = 1024;

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
        var ivMain = inStream.ReadBytes(16);

        var kdf = new Sha256IterativeKeyDerivation();
        using var key = new SensitiveData(kdf.DeriveKey(password, ivMain));

        var mainKeyAndIvRead = inStream.ReadBytes(48);

        using var hmac1 = new HMACSHA256(key);

        // HMAC without version byte
        var hmacMainIvAndKeyActual = hmac1.ComputeHash(mainKeyAndIvRead);

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

        _ = _aesCryptHeader.ReadHeader(inStream);
        var ivMain = await inStream.ReadBytesAsync(16, cancellationToken).ConfigureAwait(false);

        var kdf = new Sha256IterativeKeyDerivation();
        using var key = new SensitiveData(kdf.DeriveKey(password, ivMain));

        var mainKeyAndIvRead = await inStream.ReadBytesAsync(48, cancellationToken).ConfigureAwait(false);

        using var hmac1 = new HMACSHA256(key);

        // HMAC without version byte
        var hmacMainIvAndKeyActual = hmac1.ComputeHash(mainKeyAndIvRead);

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

        var endPositionEncryptedData = inStream.Length - 32 - 1;
        if (endPositionEncryptedData < currentPosition)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }

        // Get padding and hmac
        inStream.Position = endPositionEncryptedData;
        var moduloByte = inStream.ReadBytes(1)[0];
        if (moduloByte >= AesBlockSize)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }
        var padding = (16 - moduloByte) % 16;
        var hmacEncryptedData = inStream.ReadBytes(32);

        // Reset the position to the beginning of the encrypted data
        inStream.Position = currentPosition;

        // Get hmac
        using var hmac0 = new HMACSHA256(internalKey);
        hmac0.Initialize();

        // Get the cipher
        using var cipher = AesFactory.Create(internalKey, dataIv, usePkcs7Padding: false);
        using var decrypter = cipher.CreateDecryptor();

        // First read as much data as possible.
        ReadEncryptedBytes(inStream, outStream, hmac0, decrypter, endPositionEncryptedData, bufferSize);

        // read the remaining
        ReadEncryptedBytes(inStream, outStream, hmac0, decrypter, endPositionEncryptedData);

        // Everything read but the last block need to remove padding
        if (inStream.Position != endPositionEncryptedData)
        {
            var lastBlock = inStream.ReadBytes(AesBlockSize);
            hmac0.TransformBlock(lastBlock, 0, lastBlock.Length, null, 0);
            decrypter.TransformBlock(lastBlock, 0, lastBlock.Length, lastBlock, 0);
            outStream.Write(lastBlock, 0, lastBlock.Length - padding);
        }

        decrypter.TransformFinalBlock([], 0, 0);
        hmac0.TransformFinalBlock([], 0, 0);
        if (!CryptographicOperations.FixedTimeEquals(hmac0.Hash!, hmacEncryptedData))
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }
    }

    private static async Task DecryptAsync(Stream inStream, Stream outStream, byte[] internalKey, byte[] dataIv, int bufferSize, CancellationToken cancellationToken)
    {
        var currentPosition = inStream.Position;

        var endPositionEncryptedData = inStream.Length - 32 - 1;
        if (endPositionEncryptedData < currentPosition)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }

        // Get padding and hmac
        inStream.Position = endPositionEncryptedData;
        var moduloByte = (await inStream.ReadBytesAsync(1, cancellationToken).ConfigureAwait(false))[0];
        if (moduloByte >= AesBlockSize)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }
        var padding = (16 - moduloByte) % 16;
        var hmacEncryptedData = await inStream.ReadBytesAsync(32, cancellationToken).ConfigureAwait(false);

        // Reset the position to the beginning of the encrypted data
        inStream.Position = currentPosition;

        // Get hmac
        using var hmac0 = new HMACSHA256(internalKey);
        hmac0.Initialize();

        // Get the cipher
        using var cipher = AesFactory.Create(internalKey, dataIv, usePkcs7Padding: false);
        using var decrypter = cipher.CreateDecryptor();

        // First read as much data as possible.
        await ReadEncryptedBytesAsync(inStream, outStream, hmac0, decrypter, endPositionEncryptedData, bufferSize, cancellationToken).ConfigureAwait(false);

        // read the remaining
        await ReadEncryptedBytesAsync(inStream, outStream, hmac0, decrypter, endPositionEncryptedData, AesBlockSize, cancellationToken).ConfigureAwait(false);

        // Everything read but the last block need to remove padding
        if (inStream.Position != endPositionEncryptedData)
        {
            var lastBlock = await inStream.ReadBytesAsync(AesBlockSize, cancellationToken).ConfigureAwait(false);
            hmac0.TransformBlock(lastBlock, 0, lastBlock.Length, null, 0);
            decrypter.TransformBlock(lastBlock, 0, lastBlock.Length, lastBlock, 0);
            await outStream.WriteAsync(lastBlock.AsMemory(0, lastBlock.Length - padding), cancellationToken).ConfigureAwait(false);
        }

        decrypter.TransformFinalBlock([], 0, 0);
        hmac0.TransformFinalBlock([], 0, 0);
        if (!CryptographicOperations.FixedTimeEquals(hmac0.Hash!, hmacEncryptedData))
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt);
        }
    }

    private static void ReadEncryptedBytes(Stream inStream, Stream outStream, HMACSHA256 hmac, ICryptoTransform decrypter, long endPositionEncryptedData, int bytesToRead = AesBlockSize)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
        try
        {
            while (inStream.Position < endPositionEncryptedData - bytesToRead)
            {
                var totalBytesRead = 0;
                while (totalBytesRead < bytesToRead)
                {
                    var bytesReadInIteration = inStream.Read(buffer, totalBytesRead, bytesToRead - totalBytesRead);
                    if (bytesReadInIteration == 0)
                    {
                        throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                    }
                    totalBytesRead += bytesReadInIteration;
                }
                hmac.TransformBlock(buffer, 0, totalBytesRead, null, 0);
                decrypter.TransformBlock(buffer, 0, totalBytesRead, buffer, 0);
                outStream.Write(buffer, 0, totalBytesRead);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static async Task ReadEncryptedBytesAsync(Stream inStream, Stream outStream, HMACSHA256 hmac, ICryptoTransform decrypter, long endPositionEncryptedData, int bytesToRead, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
        try
        {
            while (inStream.Position < endPositionEncryptedData - bytesToRead)
            {
                var totalBytesRead = 0;
                while (totalBytesRead < bytesToRead)
                {
                    var bytesReadInIteration = await inStream.ReadAsync(buffer.AsMemory(totalBytesRead, bytesToRead - totalBytesRead), cancellationToken).ConfigureAwait(false);
                    if (bytesReadInIteration == 0)
                    {
                        throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                    }
                    totalBytesRead += bytesReadInIteration;
                }
                hmac.TransformBlock(buffer, 0, totalBytesRead, null, 0);
                decrypter.TransformBlock(buffer, 0, totalBytesRead, buffer, 0);
                await outStream.WriteAsync(buffer.AsMemory(0, totalBytesRead), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}
