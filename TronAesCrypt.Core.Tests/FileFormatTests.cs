using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AutoFixture;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests
{
    public class FileFormatTests : IDisposable
    {
        private const string Password = "Password1234";
        private static readonly string CreatedBy = "CREATED_BY";
        private static readonly string AppName = $"{AesCryptHeader.AppName} {AesCryptHeader.Version}";

        private readonly Fixture _fixture;
        private readonly string _workingDir;

        private readonly Dictionary<string, int> _fileInfo = new()
        {
            ["empty"] = 0,
            ["xs"] = 16,
            ["s"] = 230,
            ["l"] = 143526,
            ["xl"] = 1616161,
            ["xxl"] = 46851123
        };

        public FileFormatTests()
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
        public void TheHeaderIsCorrectlyWritten()
        {
            // Arrange
            var crypter = new AesCrypt();
            using var inStream = new MemoryStream();
            using var outStream = new MemoryStream();
            var password = _fixture.Create<string>();
            const int bufferSize = 16;

            // Act
            crypter.EncryptStream(inStream, outStream, password, bufferSize);

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

            Assert.Equal(0, outStream.ReadByte());

            buf = new byte[AppName.Length];
            outStream.Read(buf, 0, buf.Length);
            Assert.Equal(AppName, buf.GetUtf8String());

            Assert.Equal(0, outStream.ReadByte());
            Assert.Equal(128, outStream.ReadByte());

            for (var i = 0; i < 128; i++)
            {
                Assert.Equal(0, outStream.ReadByte());
            }

            Assert.Equal(0, outStream.ReadByte());
            Assert.Equal(0, outStream.ReadByte());
        }

        [Fact]
        public void TheHeaderShouldBeReadCorrectly()
        {
            using var inStream = new MemoryStream();
            using var outStream = new MemoryStream();
            var crypter = new AesCrypt();
            crypter.EncryptStream(inStream, outStream, Password, 64 * 1024);

            // Act & Assert
            crypter.DecryptStream(outStream, new MemoryStream(), Password, 64 * 1024);
        }

        [Fact]
        public async Task TheStreamShouldBeEncryptedAndDecryptedCorrectly()
        {
            foreach (var info in _fileInfo)
            {
                // Arrange
                var fileName = Path.Combine(_workingDir, info.Key);
                var file = await WriteFileToWorkingDirectory(fileName, info.Value);
                var encryptedFileName = Path.Combine(_workingDir, $"{fileName}.aes");
                var decryptedFileName = Path.Combine(_workingDir, $"{fileName}-decrypted.txt");

                // Act
                var crypter = new AesCrypt();
                crypter.EncryptFile(file, encryptedFileName, Password, 64 * 1024);
                crypter.DecryptFile(encryptedFileName, decryptedFileName, Password, 64 * 1024);

                // Assert
                Assert.Equal(fileName.AsSha256OfFile(), decryptedFileName.AsSha256OfFile());

            }
        }

        private async Task<string> WriteFileToWorkingDirectory(string fileName, int fileSize = 0)
        {
            var file = Path.Combine(_workingDir, fileName);
            await using var fs = File.Create(file);
            if (fileSize > 0)
            {
                await fs.WriteAsync(RandomSaltGenerator.Generate(fileSize));
            }

            await fs.FlushAsync();
            fs.Close();
            return file;
        }
    }
}
