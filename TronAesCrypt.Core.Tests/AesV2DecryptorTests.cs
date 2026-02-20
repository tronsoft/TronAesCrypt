using System;
using System.IO;
using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class AesV2DecryptorTests
{
    private const int AesBlockSize = 16;
    private const int KeySize = 32;

    private readonly Fixture _fixture = new();

    [Fact]
    public void Decrypt_WithValidV2Ciphertext_ReturnsOriginalPlaintext()
    {
        // Arrange
        var plaintext = _fixture.Create<byte[]>();
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(AesBlockSize);
        using var inStream = BuildV2CiphertextStream(plaintext, internalKey, dataIv);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        decryptor.Decrypt(inStream, outStream, internalKey, dataIv, 64 * 1024);

        // Assert
        outStream.ToArray().Should().Equal(plaintext);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(230)]
    [InlineData(1024)]
    public void Decrypt_WithVariousFileSizes_DecryptsCorrectly(int dataSize)
    {
        // Arrange
        var plaintext = dataSize > 0 ? RandomSaltGenerator.Generate(dataSize) : Array.Empty<byte>();
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(AesBlockSize);
        using var inStream = BuildV2CiphertextStream(plaintext, internalKey, dataIv);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        decryptor.Decrypt(inStream, outStream, internalKey, dataIv, 64 * 1024);

        // Assert
        outStream.ToArray().Should().Equal(plaintext);
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ThrowsInvalidOperationException()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(32);
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(AesBlockSize);
        var streamBytes = BuildV2CiphertextStream(plaintext, internalKey, dataIv).ToArray();

        // Flip a byte in the middle of the ciphertext
        streamBytes[0] ^= 0xFF;

        using var inStream = new MemoryStream(streamBytes);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        var act = () => decryptor.Decrypt(inStream, outStream, internalKey, dataIv, 16);

        // Assert
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(48);
        var internalKey = RandomSaltGenerator.Generate(KeySize);
        var dataIv = RandomSaltGenerator.Generate(AesBlockSize);
        using var inStream = BuildV2CiphertextStream(plaintext, internalKey, dataIv);

        var wrongKey = RandomSaltGenerator.Generate(KeySize);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        var act = () => decryptor.Decrypt(inStream, outStream, wrongKey, dataIv, 16);

        // Assert
        act.Should().Throw<InvalidOperationException>();
    }

    /// <summary>
    /// Builds a raw v2 ciphertext stream suitable for passing directly to <see cref="AesV2Decryptor.Decrypt"/>.
    /// Format: [AES-256-CBC ciphertext] [modulo byte = plaintext.Length % 16] [HMAC-SHA256 of ciphertext]
    /// </summary>
    private static MemoryStream BuildV2CiphertextStream(byte[] plaintext, byte[] internalKey, byte[] dataIv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = internalKey;
        aes.IV = dataIv;

        using var ciphertextBuffer = new MemoryStream();
        using (var cryptoStream = new CryptoStream(ciphertextBuffer, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
        {
            cryptoStream.Write(plaintext, 0, plaintext.Length);

            // Apply manual v2 padding to reach a full AES block boundary
            var remainder = plaintext.Length % AesBlockSize;
            if (remainder != 0)
            {
                var padLen = AesBlockSize - remainder;
                var padding = new byte[padLen];
                for (var i = 0; i < padLen; i++)
                {
                    padding[i] = (byte)padLen;
                }
                cryptoStream.Write(padding, 0, padding.Length);
            }

            cryptoStream.FlushFinalBlock();
        }

        var ciphertext = ciphertextBuffer.ToArray();

        using var hmac = new HMACSHA256(internalKey);
        var hmacBytes = hmac.ComputeHash(ciphertext);

        var result = new MemoryStream();
        result.Write(ciphertext, 0, ciphertext.Length);
        result.WriteByte((byte)(plaintext.Length % AesBlockSize));
        result.Write(hmacBytes, 0, hmacBytes.Length);
        result.Position = 0;
        return result;
    }
}
