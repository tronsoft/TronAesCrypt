using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
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
        private string _workingDir;

        private Dictionary<string, int> _fileInfo = new Dictionary<string, int>
        {
            ["empty"] = 0,
            ["xs"] = 16,
            ["s"] = 230,
            ["l"] = 143526,
            ["xl"] = 1616161,
            ["xxl"] = 46851123
        };
        
        [TestInitialize]
        public void Setup()
        {
            AesCryptProcessRunner.CanAesCryptRun().Should().BeTrue("AesCrypt must be in %PATH%");
            
            _fixture = new Fixture();
            _workingDir = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(Path.GetRandomFileName()));
            if (Directory.Exists(_workingDir))
            {
                Directory.Delete(_workingDir, recursive: true);
            }
            Directory.CreateDirectory(_workingDir);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_workingDir))
            {
                Directory.Delete(_workingDir, recursive: true);
            }
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
        public async Task CheckEncryptionFile()
        {
            foreach (var info in _fileInfo)
            {
                // Arrange
                var file = await WriteFileToWorkingDirectory(info.Key, info.Value);
                var encryptedFileName = $"{info.Key}.aes";
                var encryptedFile = Path.Combine(_workingDir, encryptedFileName);

                // Act
                new AesCrypt().EncryptFile(file, encryptedFile, Password, 64 * 1024);

                // Assert
                var canDecrypt = await AesCryptProcessRunner.CanDecrypt(encryptedFile, Path.Combine(_workingDir, $"{info.Key}.aescrypt.aes"), Password);
                canDecrypt.Should().BeTrue($"the encrypted file {encryptedFileName} is AesCrypt encrypted");
            }
        }

        [TestMethod]
        public void TheHeaderShouldBeReadCorrectly()
        {
            using var inStream = new MemoryStream();
            using var outStream = new MemoryStream();
            var cryptor = new AesCrypt();
            cryptor.EncryptStream(inStream, outStream, Password, 64 * 1024);
            
            // Act & Assert
            cryptor.DecryptStream(outStream, new MemoryStream(), Password, 64 * 1024);
        }
        
        [TestMethod]
        public async Task TheStreamShouldBeDecryptedCorrectly()
        {
            const string fileName = "info";
            var file = await WriteFileToWorkingDirectory(fileName, 16);
            var encryptedFileName = $"{fileName}.aes";
            var encryptedFile = Path.Combine(_workingDir, encryptedFileName);
            var cryptor = new AesCrypt();
            cryptor.EncryptFile(file, encryptedFile, Password, 64 * 1024);
            
            // Act & Assert
            await using var encFileStream = File.OpenRead(encryptedFile);
            cryptor.DecryptStream(encFileStream, new MemoryStream(), Password, 64 * 1024);
        }

        private async Task<string> WriteFileToWorkingDirectory(string fileName, int fileSize = 0)
        {
            var file = Path.Combine(_workingDir, fileName);
            await using var fs = File.Create(file);
            if (fileSize > 0)
            {
                await fs.WriteAsync(AesCrypt.GenerateRandomSalt(fileSize));
            }

            await fs.FlushAsync();
            fs.Close();
            return file;
        }
    }
}
