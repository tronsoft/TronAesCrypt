using System;
using System.IO;
using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using TRONSoft.TronAesCrypt.Core.Decryptors;
using TRONSoft.TronAesCrypt.Core.Extensions;
using TRONSoft.TronAesCrypt.Core.Helpers;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class AesV2DecryptorTests
{
    private const string Password = "Password1234";
    private const string WrongPassword = "WrongPassword!";
    private const int AesBlockSize = 16;
    private const int KeySize = 32;
    private const int HmacSize = 32;

    private readonly Fixture _fixture = new();

    [Fact]
    public void Decrypt_WithValidV2Ciphertext_ReturnsOriginalPlaintext()
    {
        // Arrange
        var plaintext = _fixture.Create<byte[]>();
        using var inStream = BuildV2FileStream(plaintext, Password);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        decryptor.DecryptStream(inStream, outStream, Password, 64 * 1024);

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
        var plaintext = dataSize > 0 ? RandomSaltGenerator.Generate(dataSize) : [];
        using var inStream = BuildV2FileStream(plaintext, Password);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        decryptor.DecryptStream(inStream, outStream, Password, 64 * 1024);

        // Assert
        outStream.ToArray().Should().Equal(plaintext);
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ThrowsInvalidOperationException()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(32);
        var streamBytes = BuildV2FileStream(plaintext, Password).ToArray();

        // Flip the last ciphertext byte (just before the 32-byte final HMAC)
        streamBytes[streamBytes.Length - HmacSize - 1] ^= 0xFF;

        using var inStream = new MemoryStream(streamBytes);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        var act = () => decryptor.DecryptStream(inStream, outStream, Password, 16);

        // Assert
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var plaintext = RandomSaltGenerator.Generate(48);
        using var inStream = BuildV2FileStream(plaintext, Password);
        using var outStream = new MemoryStream();
        var decryptor = new AesV2Decryptor();

        // Act
        var act = () => decryptor.DecryptStream(inStream, outStream, WrongPassword, 16);

        // Assert
        act.Should().Throw<InvalidOperationException>();
    }

    /// <summary>
    /// Builds a complete v2-format AES Crypt file stream from plaintext and a password.
    /// Format: [header] [ivMainKey] [encrypted session IV+key] [HMAC1] [ciphertext] [modulo byte] [HMAC2]
    /// </summary>
    private static MemoryStream BuildV2FileStream(byte[] plaintext, string password)
    {
        var outStream = new MemoryStream();

        // Write v2 header (minimal: no extensions)
        outStream.Write("AES"u8.ToArray());
        outStream.WriteByte(2);
        outStream.WriteByte(0);
        outStream.WriteByte(0);
        outStream.WriteByte(0);

        var ivMainKey = RandomSaltGenerator.Generate(AesBlockSize);
        var ivData = RandomSaltGenerator.Generate(AesBlockSize);
        var internalKey = RandomSaltGenerator.Generate(KeySize);

        var key = StretchPasswordV2(password, ivMainKey);

        outStream.Write(ivMainKey, 0, ivMainKey.Length);

        var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);
        outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);

        using (var hmac1 = new HMACSHA256(key))
        {
            var hash = hmac1.ComputeHash(encryptedMainKeyIv);
            outStream.Write(hash, 0, hash.Length);
        }

        var (encryptedData, hmacData) = EncryptDataV2(plaintext, internalKey, ivData);
        outStream.Write(encryptedData, 0, encryptedData.Length);
        outStream.WriteByte((byte)(plaintext.Length % AesBlockSize));
        outStream.Write(hmacData, 0, hmacData.Length);

        outStream.Position = 0;
        return outStream;
    }

    private static byte[] StretchPasswordV2(string password, byte[] iv)
    {
        var passwordBytes = password.GetUtf16Bytes();
        var key = new byte[KeySize];
        System.Array.Copy(iv, key, AesBlockSize);

        for (var i = 0; i < 8192; i++)
        {
            using var sha256 = SHA256.Create();
            var combined = new byte[key.Length + passwordBytes.Length];
            System.Array.Copy(key, combined, key.Length);
            System.Array.Copy(passwordBytes, 0, combined, key.Length, passwordBytes.Length);
            key = sha256.ComputeHash(combined);
        }

        return key;
    }

    private static byte[] EncryptMainKeyAndIv(byte[] key, byte[] iv, byte[] internalKey, byte[] ivInternal)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = iv;

        using var ms = new MemoryStream();
        using var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(ivInternal, 0, ivInternal.Length);
        cryptoStream.Write(internalKey, 0, internalKey.Length);
        cryptoStream.FlushFinalBlock();

        return ms.ToArray();
    }

    private static (byte[], byte[]) EncryptDataV2(byte[] plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = iv;

        using var ms = new MemoryStream();
        using var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(plaintext, 0, plaintext.Length);

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
        var encrypted = ms.ToArray();

        using var hmac = new HMACSHA256(key);
        var hmacData = hmac.ComputeHash(encrypted);

        return (encrypted, hmacData);
    }
}
