using System;
using System.IO;
using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class AesV3DecryptorTests
{
    private const int KeySize = 32;
    private const int IvSize = 16;
    private const int HmacSize = 32;
    private const int DefaultBufferSize = 64 * 1024;

    /// <summary>
    /// Builds a v3 ciphertext stream: [AES-256-CBC/PKCS#7 ciphertext] [32-byte HMAC-SHA256 of ciphertext].
    /// </summary>
    private static MemoryStream BuildV3CiphertextStream(byte[] plaintext, byte[] internalKey, byte[] dataIv)
    {
        byte[] ciphertext;
        using (var aes = AesFactory.Create(internalKey, dataIv, usePkcs7Padding: true))
        using (var encryptor = aes.CreateEncryptor())
        {
            using var msIn = new MemoryStream(plaintext);
            using var msOut = new MemoryStream();
            using (var cs = new CryptoStream(msOut, encryptor, CryptoStreamMode.Write))
            {
                msIn.CopyTo(cs);
            }
            ciphertext = msOut.ToArray();
        }

        using var hmac = new HMACSHA256(internalKey);
        var mac = hmac.ComputeHash(ciphertext);

        var result = new MemoryStream(ciphertext.Length + HmacSize);
        result.Write(ciphertext, 0, ciphertext.Length);
        result.Write(mac, 0, mac.Length);
        result.Position = 0;
        return result;
    }

    [Fact]
    public void Decrypt_WithValidV3Ciphertext_ReturnsOriginalPlaintext()
    {
        // Arrange
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(IvSize);
        var plaintext = RandomSaltGenerator.Generate(230);
        var sut = new AesV3Decryptor();

        using var inStream = BuildV3CiphertextStream(plaintext, internalKey, dataIv);
        using var outStream = new MemoryStream();

        // Act
        sut.Decrypt(inStream, outStream, internalKey, dataIv, DefaultBufferSize);

        // Assert
        outStream.ToArray().Should().Equal(plaintext);
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
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(IvSize);
        var plaintext = plaintextSize == 0 ? [] : RandomSaltGenerator.Generate(plaintextSize);
        var sut = new AesV3Decryptor();

        using var inStream = BuildV3CiphertextStream(plaintext, internalKey, dataIv);
        using var outStream = new MemoryStream();

        // Act
        sut.Decrypt(inStream, outStream, internalKey, dataIv, DefaultBufferSize);

        // Assert
        outStream.ToArray().Should().Equal(plaintext);
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ThrowsInvalidOperationException()
    {
        // Arrange
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(IvSize);
        var plaintext = RandomSaltGenerator.Generate(64);
        var sut = new AesV3Decryptor();

        var streamBytes = BuildV3CiphertextStream(plaintext, internalKey, dataIv).ToArray();
        // Flip a byte in the ciphertext (before the last 32 HMAC bytes)
        streamBytes[0] ^= 0xFF;

        using var inStream = new MemoryStream(streamBytes);
        using var outStream = new MemoryStream();

        // Act
        var act = () => sut.Decrypt(inStream, outStream, internalKey, dataIv, DefaultBufferSize);

        // Assert
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(IvSize);
        var plaintext = RandomSaltGenerator.Generate(64);
        var sut = new AesV3Decryptor();

        using var inStream = BuildV3CiphertextStream(plaintext, internalKey, dataIv);

        var wrongKey = RandomSaltGenerator.Generate(KeySize);
        using var outStream = new MemoryStream();

        // Act
        var act = () => sut.Decrypt(inStream, outStream, wrongKey, dataIv, DefaultBufferSize);

        // Assert
        act.Should().Throw<InvalidOperationException>();
    }
}
