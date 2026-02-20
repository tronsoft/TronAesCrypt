using System;
using System.IO;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class KdfValidationTests
{
    private const string Password = "Password1234";

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    [InlineData(9_999)]           // Just below minimum
    [InlineData(10_000_001)]      // Just above maximum
    [InlineData(100_000_000)]     // Way above maximum
    public void DecryptStream_WithInvalidKdfIterations_Throws(int invalidIterations)
    {
        // Arrange
        var crypter = new AesCrypt();
        using var outStream = new MemoryStream();
        
        // Manually construct a v3 encrypted stream with invalid KDF iterations
        var inStream = CreateV3StreamWithSpecificKdfIterations(invalidIterations);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => 
            crypter.DecryptStream(inStream, outStream, Password, 16));
    }

    [Theory]
    [InlineData(10_000)]      // Minimum valid
    [InlineData(10_001)]
    [InlineData(300_000)]     // Default
    [InlineData(9_999_999)]
    [InlineData(10_000_000)]  // Maximum valid
    public void DecryptStream_WithValidKdfIterations_DoesNotThrow(int validIterations)
    {
        // Arrange - Create a properly encrypted v3 stream
        var testData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var crypter = new AesCrypt();
        
        using var inputStream = new MemoryStream(testData);
        using var encryptedStream = new MemoryStream();
        crypter.EncryptStream(inputStream, encryptedStream, Password, 16, validIterations);

        // Act - Should not throw
        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();
        crypter.DecryptStream(encryptedStream, decryptedStream, Password, 16);

        // Assert
        Assert.Equal(testData, decryptedStream.ToArray());
    }

    /// <summary>
    /// Creates a minimal v3 stream with specific KDF iteration count.
    /// This stream won't decrypt properly (no valid data), but will test KDF validation.
    /// </summary>
    private static MemoryStream CreateV3StreamWithSpecificKdfIterations(int kdfIterations)
    {
        var stream = new MemoryStream();
        
        // Write magic bytes "AES"
        stream.Write("AES"u8.ToArray());
        
        // Write version byte (3 for v3)
        stream.WriteByte(3);
        
        // Write reserved byte
        stream.WriteByte(0);
        
        // Write minimal extensions (just end-of-extensions marker)
        stream.WriteByte(0);
        stream.WriteByte(0);
        
        // Write KDF iteration count (4 bytes, big-endian)
        var iterationBytes = BitConverter.GetBytes(kdfIterations);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        stream.Write(iterationBytes, 0, iterationBytes.Length);
        
        // Write dummy IV (16 bytes)
        stream.Write(new byte[16]);
        
        // Write dummy encrypted key+IV (48 bytes)
        stream.Write(new byte[48]);
        
        // Write dummy HMAC (32 bytes)
        stream.Write(new byte[32]);
        
        // Reset position to beginning
        stream.Position = 0;
        return stream;
    }
}
