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
