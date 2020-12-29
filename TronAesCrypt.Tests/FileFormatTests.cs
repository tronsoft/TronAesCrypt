using System.IO;
using System.Text;
using AutoFixture;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TRONSoft.TronAesCrypt.Core;

namespace TRONSoft.TronAesCrypt.Main
{
    [TestClass]
    public class FileFormatTests
    {
        private static readonly string CreatedBy = "CREATED_BY";
        private static readonly string AppName = "TronAesCrypt";
        
        private Fixture _fixture;
        
        [TestInitialize]
        public void Setup()
        {
            _fixture = new Fixture();
        }
        
        [TestMethod]
        public void TheHeaderIsCorrectlyWritten()
        {
            // Arrange
            var cryptor = new AesCrypt();
            using var inStream = new MemoryStream();
            using var outStream = new MemoryStream();
            var password = _fixture.Create<string>();
            int bufferSize = 16;

            // Act
            cryptor.EncryptStream(inStream, outStream, password, bufferSize);

            // Assert
            var buf = new byte[3];
            outStream.Read(buf, 0, buf.Length);
            buf.GetUtf8String().Should().Be("AES", "This is in the standard");
            outStream.ReadByte().Should().Be(2, "This is in the standard");
            outStream.ReadByte().Should().Be(0, "This is in the standard");
            outStream.ReadByte().Should().Be(0, "This is in the standard");
            outStream.ReadByte().Should().Be((CreatedBy + AppName).Length + 1, "This is in the standard");
            
            buf = new byte[CreatedBy.Length];
            outStream.Read(buf, 0, buf.Length);
            buf.GetUtf8String().Should().Be(CreatedBy, "This is in the standard");
            
            outStream.ReadByte().Should().Be(0, "This is in the standard");
            
            buf = new byte[AppName.Length];
            outStream.Read(buf, 0, buf.Length);
            buf.GetUtf8String().Should().Be(AppName, "This is in the standard");
            
            outStream.ReadByte().Should().Be(0, "This is in the standard");
            outStream.ReadByte().Should().Be(80, "This is in the standard");

            for (var i = 0; i < 128; i++)
            {
                outStream.ReadByte().Should().Be(0, "This is in the standard");
            }
            
            outStream.ReadByte().Should().Be(0, "This is in the standard");
            outStream.ReadByte().Should().Be(0, "This is in the standard");
        }
        
        [TestMethod]
        public void WriteAFile()
        {
            // Arrange
            var encryptedFile = @"e:\tmp\input.txt.aes";
            File.Delete(encryptedFile);
            new AesCrypt().EncryptFile(@"e:\tmp\input.txt", encryptedFile, "foopassword!1$A", 64 * 1024);
            
            // Act
            
            // Assert
        }
    }
}