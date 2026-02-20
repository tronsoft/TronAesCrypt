using System;
using System.IO;
using System.Security.Cryptography;
using AutoFixture;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

/// <summary>
/// Tests for backward compatibility with AES Crypt v2 file format.
/// V2 uses SHA-256 iterative key derivation (8192 iterations) instead of PBKDF2-HMAC-SHA512.
/// </summary>
public class V2BackwardCompatibilityTests : IDisposable
{
    private const string Password = "Password1234";
    private readonly Fixture _fixture;
    private readonly string _workingDir;

    public V2BackwardCompatibilityTests()
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

    [Fact]
    public void DecryptStream_WithV2FormatFile_DecryptsSuccessfully()
    {
        // Arrange - Create a v2 encrypted stream
        var originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var v2EncryptedStream = CreateV2EncryptedStream(originalData, Password);
        
        var crypter = new AesCrypt();
        using var decryptedStream = new MemoryStream();

        // Act
        v2EncryptedStream.Position = 0;
        crypter.DecryptStream(v2EncryptedStream, decryptedStream, Password, 16);

        // Assert
        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Theory]
    [InlineData(0)]      // Empty file
    [InlineData(16)]     // Exactly one AES block
    [InlineData(32)]     // Two blocks
    [InlineData(230)]    // Multiple blocks with padding
    [InlineData(1024)]   // Larger file
    public void DecryptStream_WithV2FormatVariousSizes_DecryptsSuccessfully(int dataSize)
    {
        // Arrange
        var originalData = dataSize > 0 ? RandomSaltGenerator.Generate(dataSize) : Array.Empty<byte>();
        var v2EncryptedStream = CreateV2EncryptedStream(originalData, Password);
        
        var crypter = new AesCrypt();
        using var decryptedStream = new MemoryStream();

        // Act
        v2EncryptedStream.Position = 0;
        crypter.DecryptStream(v2EncryptedStream, decryptedStream, Password, 64 * 1024);

        // Assert
        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Fact]
    public void DecryptFile_WithV2FormatFile_DecryptsSuccessfully()
    {
        // Arrange
        var originalData = _fixture.Create<byte[]>();
        var originalFile = Path.Combine(_workingDir, "original.txt");
        File.WriteAllBytes(originalFile, originalData);
        
        var v2EncryptedFile = Path.Combine(_workingDir, "encrypted-v2.aes");
        CreateV2EncryptedFile(originalFile, v2EncryptedFile, Password);
        
        var decryptedFile = Path.Combine(_workingDir, "decrypted.txt");
        var crypter = new AesCrypt();

        // Act
        crypter.DecryptFile(v2EncryptedFile, decryptedFile, Password, 64 * 1024);

        // Assert
        Assert.Equal(originalFile.AsSha256OfFile(), decryptedFile.AsSha256OfFile());
    }

    [Fact]
    public void DecryptStream_WithV2FormatWrongPassword_Throws()
    {
        // Arrange
        var originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var v2EncryptedStream = CreateV2EncryptedStream(originalData, Password);
        
        var crypter = new AesCrypt();
        using var decryptedStream = new MemoryStream();

        // Act & Assert
        v2EncryptedStream.Position = 0;
        Assert.Throws<InvalidOperationException>(() => 
            crypter.DecryptStream(v2EncryptedStream, decryptedStream, "WrongPassword", 16));
    }

    /// <summary>
    /// Creates a v2 encrypted stream using SHA-256 iterative KDF (8192 iterations).
    /// This manually implements v2 encryption to test backward compatibility.
    /// </summary>
    private static MemoryStream CreateV2EncryptedStream(byte[] plaintext, string password)
    {
        const int aesBlockSize = 16;
        const int keySize = 32;
        
        var outStream = new MemoryStream();
        
        // Write v2 header
        outStream.Write("AES"u8.ToArray());
        outStream.WriteByte(2); // Version 2
        outStream.WriteByte(0); // Reserved
        
        // Write minimal extensions (just end-of-extensions marker)
        outStream.WriteByte(0);
        outStream.WriteByte(0);
        
        // Note: V2 does NOT have KDF iteration field - that's a v3 feature
        
        // Generate random IVs and keys
        var ivMainKey = RandomSaltGenerator.Generate(aesBlockSize);
        var ivData = RandomSaltGenerator.Generate(aesBlockSize);
        var internalKey = RandomSaltGenerator.Generate(keySize);
        
        // Derive key using SHA-256 iterative KDF (v2 method)
        var key = StretchPasswordV2(password, ivMainKey);
        
        // Write ivMainKey
        outStream.Write(ivMainKey, 0, ivMainKey.Length);
        
        // Encrypt the internal key and IV
        var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);
        outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);
        
        // Write HMAC of encrypted key+IV (v2: without version byte)
        using (var hmac1 = new HMACSHA256(key))
        {
            var hash = hmac1.ComputeHash(encryptedMainKeyIv);
            outStream.Write(hash, 0, hash.Length);
        }
        
        // Encrypt the data with custom v2 padding
        var (moduloByte, hmacData) = EncryptDataV2(plaintext, internalKey, ivData);
        outStream.Write(moduloByte, 0, moduloByte.Length);
        
        // Write modulo byte
        outStream.WriteByte((byte)(plaintext.Length % 16));
        
        // Write HMAC of encrypted data
        outStream.Write(hmacData, 0, hmacData.Length);
        
        outStream.Position = 0;
        return outStream;
    }

    private static void CreateV2EncryptedFile(string inputFile, string outputFile, string password)
    {
        var plaintext = File.ReadAllBytes(inputFile);
        using var encryptedStream = CreateV2EncryptedStream(plaintext, password);
        using var fileStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
        encryptedStream.CopyTo(fileStream);
    }

    /// <summary>
    /// V2 key derivation: SHA-256 iterated 8192 times.
    /// </summary>
    private static byte[] StretchPasswordV2(string password, byte[] iv)
    {
        var passwordBytes = password.GetUtf16Bytes();
        var key = new byte[32];
        Array.Copy(iv, key, 16);
        
        for (var i = 0; i < 8192; i++)
        {
            using var sha256 = SHA256.Create();
            var combined = new byte[key.Length + passwordBytes.Length];
            Array.Copy(key, combined, key.Length);
            Array.Copy(passwordBytes, 0, combined, key.Length, passwordBytes.Length);
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

    /// <summary>
    /// V2 data encryption with custom padding (not PKCS#7).
    /// Returns encrypted data and HMAC.
    /// </summary>
    private static (byte[], byte[]) EncryptDataV2(byte[] plaintext, byte[] key, byte[] iv)
    {
        const int aesBlockSize = 16;
        
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = iv;
        
        using var ms = new MemoryStream();
        using var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        
        // Write plaintext
        cryptoStream.Write(plaintext, 0, plaintext.Length);
        
        // Add custom v2 padding if needed
        var remainder = plaintext.Length % aesBlockSize;
        if (remainder != 0)
        {
            var padLen = aesBlockSize - remainder;
            var padding = new byte[padLen];
            for (var i = 0; i < padLen; i++)
            {
                padding[i] = (byte)padLen;
            }
            cryptoStream.Write(padding, 0, padding.Length);
        }
        
        cryptoStream.FlushFinalBlock();
        var encrypted = ms.ToArray();
        
        // Compute HMAC of encrypted data
        using var hmac = new HMACSHA256(key);
        var hmacData = hmac.ComputeHash(encrypted);
        
        return (encrypted, hmacData);
    }
}
