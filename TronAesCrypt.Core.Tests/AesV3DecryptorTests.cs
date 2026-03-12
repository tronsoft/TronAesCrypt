using System;
using System.IO;
using TRONSoft.TronAesCrypt.Core.Decryptors;
using TRONSoft.TronAesCrypt.Core.Helpers;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class AesV3DecryptorTests
{
    private const string Password = "Password1234";
    private const string WrongPassword = "WrongPassword!";
    private const int HmacSize = 32;
    private const int DefaultBufferSize = 64 * 1024;
    private const int TestKdfIterations = 10_000;

    [Fact]
    public void Decrypt_WithValidV3Ciphertext_ReturnsOriginalPlaintext()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(230);
        var sut = new AesV3Decryptor();

        using var inStream = BuildV3FileStream(plaintext, Password);
        using var outStream = new MemoryStream();

        // Act
        sut.DecryptStream(inStream, outStream, Password, DefaultBufferSize);

        // Assert
        Assert.Equal(plaintext, outStream.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(230)]
    [InlineData(1024)]
    public void Decrypt_WithVariousFileSizes_DecryptsCorrectly(int plaintextSize)
    {
        // Arrange
        var plaintext = plaintextSize == 0 ? [] : RandomSaltGenerator.Generate(plaintextSize);
        var sut = new AesV3Decryptor();

        using var inStream = BuildV3FileStream(plaintext, Password);
        using var outStream = new MemoryStream();

        // Act
        sut.DecryptStream(inStream, outStream, Password, DefaultBufferSize);

        // Assert
        Assert.Equal(plaintext, outStream.ToArray());
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ThrowsInvalidOperationException()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(64);
        var sut = new AesV3Decryptor();

        var streamBytes = BuildV3FileStream(plaintext, Password).ToArray();
        // Flip the last ciphertext byte (just before the 32-byte final HMAC)
        streamBytes[streamBytes.Length - HmacSize - 1] ^= 0xFF;

        using var inStream = new MemoryStream(streamBytes);
        using var outStream = new MemoryStream();

        // Act
        var act = () => sut.DecryptStream(inStream, outStream, Password, DefaultBufferSize);

        // Assert
        Assert.Throws<InvalidOperationException>(act);
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(64);
        var sut = new AesV3Decryptor();

        using var inStream = BuildV3FileStream(plaintext, Password);
        using var outStream = new MemoryStream();

        // Act
        var act = () => sut.DecryptStream(inStream, outStream, WrongPassword, DefaultBufferSize);

        // Assert
        Assert.Throws<InvalidOperationException>(act);
    }

    /// <summary>
    /// Verifies decryption of the official AES Crypt 4.x reference file (hello_world.txt)
    /// published at https://www.aescrypt.com/hello_world.txt.
    /// Encrypted with password "apples", plaintext is "Hello, World!\n" (14 bytes).
    /// This test guards against regressions in cross-implementation interoperability.
    /// </summary>
    [Fact]
    public void Decrypt_OfficialReferenceFile_ReturnsHelloWorld()
    {
        // Official hello_world.txt hex dump from aescrypt.com (188 bytes, password "apples")
        byte[] referenceFile =
        [
            0x41, 0x45, 0x53, 0x03, 0x00, 0x00, 0x1F, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x44, 0x5F, 0x42,
            0x59, 0x00, 0x61, 0x65, 0x73, 0x63, 0x72, 0x79, 0x70, 0x74, 0x5F, 0x63, 0x6C, 0x69, 0x20, 0x34,
            0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x30, 0x00, 0x00, 0x00, 0x04, 0x93, 0xE0, 0x94, 0x70, 0x21, 0xF8,
            0xEE, 0xB3, 0x2E, 0xA4, 0x4E, 0xA8, 0x23, 0x72, 0x0A, 0x91, 0x2A, 0x18, 0xD5, 0xEC, 0x63, 0xF1,
            0x41, 0x7B, 0x77, 0x37, 0xB0, 0x0C, 0x45, 0x0C, 0xE3, 0xA6, 0xCE, 0x10, 0x77, 0x89, 0x78, 0x95,
            0xED, 0x48, 0xB4, 0x56, 0x7A, 0x36, 0x04, 0x62, 0xFB, 0x24, 0x2D, 0x5C, 0x8A, 0xBC, 0x44, 0x8D,
            0x47, 0x85, 0x2E, 0xEB, 0x9D, 0xC3, 0xB7, 0x91, 0x1F, 0x4B, 0xF0, 0x02, 0xE9, 0xEE, 0x26, 0xBF,
            0xEA, 0x2F, 0xFC, 0x47, 0x12, 0xD3, 0x61, 0x98, 0x85, 0x50, 0x53, 0x45, 0xF5, 0x35, 0x73, 0x63,
            0xD9, 0x0B, 0x6A, 0x2F, 0xAC, 0x2B, 0x37, 0xD1, 0xDB, 0x8F, 0x34, 0xF6, 0x06, 0xA2, 0xDE, 0x1E,
            0x8C, 0x66, 0x2A, 0x94, 0xC0, 0x3B, 0x15, 0xFD, 0xF9, 0x4A, 0xCE, 0x23, 0x83, 0x5B, 0x90, 0x9E,
            0x3F, 0xEF, 0x96, 0xA7, 0x07, 0x14, 0x11, 0xFD, 0x72, 0x51, 0x78, 0x62, 0xCB, 0x00, 0x8C, 0xB5,
            0x90, 0xA4, 0x05, 0x65, 0x4B, 0xA8, 0xD3, 0xA7, 0x18, 0xD3, 0xA8, 0xFA
        ];

        var expectedPlaintext = "Hello, World!\n"u8.ToArray();
        var sut = new AesV3Decryptor();

        using var inStream = new MemoryStream(referenceFile);
        using var outStream = new MemoryStream();

        // Act
        sut.DecryptStream(inStream, outStream, "apples", DefaultBufferSize);

        // Assert
        Assert.Equal(expectedPlaintext, outStream.ToArray());
    }

    /// <summary>
    /// Builds a complete v3-format AES Crypt file stream from plaintext and a password.
    /// Uses a low iteration count to keep tests fast.
    /// </summary>
    private static MemoryStream BuildV3FileStream(byte[] plaintext, string password)
    {
        var outStream = new MemoryStream();
        using var inStream = new MemoryStream(plaintext);
        new AesCrypt().EncryptStream(inStream, outStream, password, 16, TestKdfIterations);
        outStream.Position = 0;
        return outStream;
    }
}
