using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Decrypts AES Crypt stream format v2 ciphertext.
/// V2 uses a modulo byte (plaintext_size % 16) before the final HMAC-SHA256.
/// </summary>
internal sealed class AesV2Decryptor : IAesDecryptor
{
    private const int AesBlockSize = 16;

    /// <inheritdoc />
    public void Decrypt(Stream inStream, Stream outStream, byte[] internalKey, byte[] dataIv, int bufferSize)
    {
        var currentPosition = inStream.Position;

        // V2: Has modulo byte before final HMAC
        var endPositionEncryptedData = inStream.Length - 32 - 1;

        // Get padding and hmac
        inStream.Position = endPositionEncryptedData;
        var padding = (16 - inStream.ReadBytes(1)[0]) % 16;
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

    private void ReadEncryptedBytes(Stream inStream, Stream outStream, HMACSHA256 hmac, ICryptoTransform decrypter, long endPositionEncryptedData, int bytesToRead = AesBlockSize)
    {
        var buffer = new byte[bytesToRead];
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
}
