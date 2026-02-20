using System;
using System.IO;
using AutoFixture;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class V3FormatTests : IDisposable
{
    private const string Password = "Password1234";
    private readonly Fixture _fixture;
    private readonly string _workingDir;

    public V3FormatTests()
    {
        _fixture = new Fixture();
        _workingDir = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(Path.GetRandomFileName()));
        if (Directory.Exists(_workingDir))
        {
            Directory.Delete(_workingDir, recursive: true);
        }
        Directory.CreateDirectory(_workingDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_workingDir))
        {
            Directory.Delete(_workingDir, recursive: true);
        }
    }

    [Theory]
    [InlineData(300_000)]
    [InlineData(100_000)]
    [InlineData(500_000)]
    [InlineData(1_000_000)]
    public void EncryptStream_WithSpecificKdfIterations_WritesIterationFieldCorrectly(int kdfIterations)
    {
        // Arrange
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();

        // Act
        crypter.EncryptStream(inStream, outStream, Password, 16, kdfIterations);

        // Assert - Verify header structure
        outStream.Position = 0;
        
        // Read magic bytes "AES"
        var magicBuf = new byte[3];
        outStream.Read(magicBuf, 0, magicBuf.Length);
        Assert.Equal("AES", magicBuf.GetUtf8String());
        
        // Read version byte (should be 3 for v3)
        Assert.Equal(3, outStream.ReadByte());
        
        // Read reserved byte
        Assert.Equal(0, outStream.ReadByte());
        
        // Skip extensions - read until we find end-of-extensions marker (0x00 0x00)
        SkipExtensions(outStream);
        
        // Now we should be at the 4-byte KDF iteration count
        var iterationBytes = new byte[4];
        var bytesRead = outStream.Read(iterationBytes, 0, iterationBytes.Length);
        Assert.Equal(4, bytesRead);
        
        // Convert from big-endian to int
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        var readIterations = BitConverter.ToInt32(iterationBytes, 0);
        
        Assert.Equal(kdfIterations, readIterations);
    }

    [Fact]
    public void EncryptDecrypt_WithSpecificKdfIterations_RoundTripsCorrectly()
    {
        // Arrange
        const int kdfIterations = 300_000;
        var testData = _fixture.Create<byte[]>();
        var crypter = new AesCrypt();
        
        using var inputStream = new MemoryStream(testData);
        using var encryptedStream = new MemoryStream();
        using var decryptedStream = new MemoryStream();

        // Act
        crypter.EncryptStream(inputStream, encryptedStream, Password, 16, kdfIterations);
        encryptedStream.Position = 0;
        crypter.DecryptStream(encryptedStream, decryptedStream, Password, 16);

        // Assert
        Assert.Equal(testData, decryptedStream.ToArray());
    }

    [Theory]
    [InlineData(10_000)]      // Minimum valid
    [InlineData(100_000)]
    [InlineData(500_000)]
    [InlineData(1_000_000)]
    [InlineData(5_000_000)]
    [InlineData(10_000_000)]  // Maximum valid
    public void DecryptStream_WithValidKdfIterations_DecryptsSuccessfully(int kdfIterations)
    {
        // Arrange
        var testData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var crypter = new AesCrypt();
        
        using var inputStream = new MemoryStream(testData);
        using var encryptedStream = new MemoryStream();
        crypter.EncryptStream(inputStream, encryptedStream, Password, 16, kdfIterations);

        // Act
        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();
        crypter.DecryptStream(encryptedStream, decryptedStream, Password, 16);

        // Assert
        Assert.Equal(testData, decryptedStream.ToArray());
    }

    /// <summary>
    /// Helper method to skip over extensions in the stream.
    /// Extensions end with a 0x00 0x00 marker.
    /// </summary>
    private static void SkipExtensions(Stream stream)
    {
        while (true)
        {
            var lengthBuf = new byte[2];
            var bytesRead = stream.Read(lengthBuf, 0, lengthBuf.Length);
            
            if (bytesRead != 2)
            {
                throw new InvalidOperationException("Unexpected end of stream while reading extensions");
            }

            // Check for end-of-extensions marker
            if (lengthBuf[0] == 0 && lengthBuf[1] == 0)
            {
                break;
            }

            // Read the length as big-endian
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(lengthBuf);
            }
            var extensionLength = BitConverter.ToInt16(lengthBuf, 0);
            
            // Skip the extension data
            var extensionData = new byte[extensionLength];
            bytesRead = stream.Read(extensionData, 0, extensionData.Length);
            
            if (bytesRead != extensionLength)
            {
                throw new InvalidOperationException("Unexpected end of stream while reading extension data");
            }
        }
    }
}
