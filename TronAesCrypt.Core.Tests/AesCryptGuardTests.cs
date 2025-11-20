using System;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class AesCryptGuardTests
{
    private const string Password = "Password1234";

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(18)]
    public void EncryptStream_WithInvalidBufferSize_Throws(int bufferSize)
    {
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();

        Assert.Throws<ArgumentException>(() => crypter.EncryptStream(inStream, outStream, Password, bufferSize));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(18)]
    public void DecryptStream_WithInvalidBufferSize_Throws(int bufferSize)
    {
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();

        Assert.Throws<ArgumentException>(() => crypter.DecryptStream(inStream, outStream, Password, bufferSize));
    }

    [Fact]
    public void EncryptStream_WithTooLongPassword_Throws()
    {
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();
        var longPassword = new string('a', 1025);

        Assert.Throws<ArgumentException>(() => crypter.EncryptStream(inStream, outStream, longPassword, 16));
    }

    [Fact]
    public void DecryptStream_WithInvalidHeader_Throws()
    {
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();

        // Write wrong 3-byte magic instead of "AES"
        inStream.Write(Encoding.ASCII.GetBytes("FOO"));
        inStream.Position = 0;

        Assert.Throws<InvalidOperationException>(() => crypter.DecryptStream(inStream, outStream, Password, 16));
    }

    [Fact]
    public void DecryptStream_WithInvalidVersion_Throws()
    {
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();

        // Write correct magic, wrong version, reserved, and end-of-extensions
        inStream.Write(Encoding.ASCII.GetBytes("AES"));
        inStream.WriteByte(3); // invalid version (valid is 2)
        inStream.WriteByte(0); // reserved
        inStream.WriteByte(0); // end of extensions tag hi
        inStream.WriteByte(0); // end of extensions tag lo
        inStream.Position = 0;

        Assert.Throws<InvalidOperationException>(() => crypter.DecryptStream(inStream, outStream, Password, 16));
    }

    [Fact]
    public void DecryptStream_WithWrongPassword_Throws()
    {
        var crypter = new AesCrypt();
        using var inStream = new MemoryStream([1, 2, 3, 4, 5, 6, 7, 8]);
        using var encrypted = new MemoryStream();
        crypter.EncryptStream(inStream, encrypted, Password, 16);

        // Try to decrypt with a wrong password
        encrypted.Position = 0;
        using var outStream = new MemoryStream();
        Assert.Throws<InvalidOperationException>(() => crypter.DecryptStream(encrypted, outStream, "WRONG-PASSWORD", 16));
    }

    [Fact]
    public void DecryptStream_WithTamperedHmac_Throws()
    {
        var crypter = new AesCrypt();
        using var input = new MemoryStream([10, 20, 30, 40, 50, 60, 70, 80]);
        using var encrypted = new MemoryStream();
        crypter.EncryptStream(input, encrypted, Password, 16);

        // Flip a bit in the last byte (part of HMAC of data)
        var bytes = encrypted.ToArray();
        bytes[^1] ^= 0x01;
        using var tampered = new MemoryStream(bytes);

        using var outStream = new MemoryStream();
        Assert.Throws<InvalidOperationException>(() => crypter.DecryptStream(tampered, outStream, Password, 16));
    }
}
