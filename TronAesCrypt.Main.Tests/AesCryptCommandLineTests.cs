using System.IO;
using System.Threading.Tasks;
using AutoFixture;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TronAesCrypt.Main.Tests
{
    [TestClass]
    public class AesCryptCommandLineTests
    {
        private readonly Fixture m_fixture = new();

        [TestMethod]
        public async Task FileIsEncryptedSuccessfully()
        {
            var fileToEncrypt = Path.GetTempFileName();
            var encryptedFile = Path.GetTempFileName();
            var password = m_fixture.Create<string>();

            await CreateTextFile(fileToEncrypt, m_fixture.Create<string>());

            AesCryptProcessRunner
                .CanEncrypt(fileToEncrypt, encryptedFile, password)
                .Should()
                .BeTrue("the file can be encrypted");
        }

        [TestMethod]
        public async Task FileIsDecryptedSuccessfully()
        {
            var fileToEncrypt = Path.GetTempFileName();
            var encryptedFile = Path.GetTempFileName();
            var decryptedFile = Path.GetTempFileName();
            var password = m_fixture.Create<string>();

            await CreateTextFile(fileToEncrypt, m_fixture.Create<string>());

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
