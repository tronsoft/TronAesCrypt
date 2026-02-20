using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Decrypts AES Crypt stream format v3 ciphertext.
/// V3 uses standard PKCS#7 padding and no modulo byte; HMAC-SHA256 is the last 32 bytes of the stream.
/// A two-pass approach is used: Pass 1 verifies the HMAC, Pass 2 decrypts the ciphertext.
/// </summary>
internal sealed class AesV3Decryptor : IAesDecryptor
{
    /// <inheritdoc />
    public void Decrypt(Stream inStream, Stream outStream, byte[] internalKey, byte[] dataIv, int bufferSize)
    {
        var currentPosition = inStream.Position;

        // V3: No modulo byte, just HMAC at the end, and uses PKCS#7 padding
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

    private sealed class LimitedReadStream : Stream
    {
        private readonly Stream _innerStream;
        private long _remaining;

        public LimitedReadStream(Stream innerStream, long maxBytes)
        {
            _innerStream = innerStream;
            _remaining = maxBytes;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0)
            {
                return 0;
            }
            var bytesToRead = (int)Math.Min(count, _remaining);
            var bytesRead = _innerStream.Read(buffer, offset, bytesToRead);
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
