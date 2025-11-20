using System.IO;
using System.Threading.Tasks;
using AutoFixture;
using FluentAssertions;
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

            AesCryptProcessRunner
                .CanEncrypt(fileToEncrypt, encryptedFile, password)
                .Should()
                .BeTrue("the file can be encrypted");
        }

        [Fact]
        public async Task FileIsDecryptedSuccessfully()
        {
            var fileToEncrypt = Path.GetTempFileName();
            var encryptedFile = Path.GetTempFileName();
            var decryptedFile = Path.GetTempFileName();
            var password = _fixture.Create<string>();

            await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

            AesCryptProcessRunner
                .CanEncrypt(fileToEncrypt, encryptedFile, password)
                .Should()
                .BeTrue("the file can be encrypted");

            AesCryptProcessRunner
                .CanDecrypt(encryptedFile, decryptedFile, password)
                .Should()
                .BeTrue("the file can be decrypted");
        }

        private static async Task CreateTextFile(string inputFileName, string content)
        {
            await using var sw = File.CreateText(inputFileName);
            await sw.WriteLineAsync(content);
            sw.Close();
        }
    }
}
