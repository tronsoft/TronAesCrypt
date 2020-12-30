using System.IO;
using AutoFixture;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TRONSoft.TronAesCrypt.Core;

namespace TRONSoft.TronAesCrypt.Main
{
    [TestClass]
    public class FileFormatTests
    {
        private const string Password = "Password1234";
        private static readonly string CreatedBy = "CREATED_BY";
        private static readonly string AppName = $"{AesCrypt.AppName} {AesCrypt.Version}";
        
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
            outStream.ReadByte().Should().Be(128, "This is in the standard");

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
            var encryptedFile = @"e:\tmp\block.aes";
            File.Delete(encryptedFile);

            // Act
            new AesCrypt().EncryptFile(@"e:\tmp\block", encryptedFile, Password, 64 * 1024);

            // Assert
        }

        [TestMethod]
        public void WriteAMediumFile()
        {
            // Arrange
            var encryptedFile = @"e:\tmp\med.aes";
            File.Delete(encryptedFile);
            
            // Act
            new AesCrypt().EncryptFile(@"e:\tmp\med", encryptedFile, Password, 64 * 1024);
            
            // Assert
        }
        
        [TestMethod]
        public void WriteAnEmptyFile()
        {
            // Arrange
            var encryptedFile = @"e:\tmp\empty.txt.aes";
            File.Delete(encryptedFile);

            // Act
            new AesCrypt().EncryptFile(@"e:\tmp\empty.txt", encryptedFile, Password, 64 * 1024);

            // Assert
        }
    }
}
