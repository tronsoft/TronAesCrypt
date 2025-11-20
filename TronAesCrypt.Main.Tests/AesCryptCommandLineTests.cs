using System.IO;
using System.Threading.Tasks;
using AutoFixture;
using Xunit;

namespace TronAesCrypt.Main.Tests
{
    public class AesCryptCommandLineTests
    {
        private readonly Fixture _fixture = new();

        [Fact]
        public async Task FileIsEncryptedSuccessfully()
        {
            var fileToEncrypt = Path.GetTempFileName();
            var encryptedFile = Path.GetTempFileName();
            var password = _fixture.Create<string>();

            await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

            Assert.True(
                AesCryptProcessRunner.CanEncrypt(fileToEncrypt, encryptedFile, password),
                "the file can be encrypted");
        }

        [Fact]
        public async Task FileIsDecryptedSuccessfully()
        {
            var fileToEncrypt = Path.GetTempFileName();
            var encryptedFile = Path.GetTempFileName();
            var decryptedFile = Path.GetTempFileName();
            var password = _fixture.Create<string>();

            await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

            Assert.True(
                AesCryptProcessRunner.CanEncrypt(fileToEncrypt, encryptedFile, password),
                "the file can be encrypted");

            Assert.True(
                AesCryptProcessRunner.CanDecrypt(encryptedFile, decryptedFile, password),
                "the file can be decrypted");
        }

        private static async Task CreateTextFile(string inputFileName, string content)
        {
            await using var sw = File.CreateText(inputFileName);
            await sw.WriteLineAsync(content);
            sw.Close();
        }
    }
}
