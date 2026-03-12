using System.IO;
using System.Threading.Tasks;
using AutoFixture;
using Xunit;

namespace TronAesCrypt.Main.Tests;

public class AesCryptCommandLineTests
{
    private readonly Fixture _fixture = new();

    // ──────────────────────────────────────────────────────────────
    // Legacy syntax: -e -f <file> -o <output> -p <password>
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task LegacySyntax_FileIsEncryptedSuccessfully()
    {
        var fileToEncrypt = Path.GetTempFileName();
        var encryptedFile = Path.GetTempFileName();
        var password = _fixture.Create<string>();
        await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

        Assert.True(AesCryptProcessRunner.CanEncrypt(fileToEncrypt, encryptedFile, password));
    }

    [Fact]
    public async Task LegacySyntax_FileIsDecryptedSuccessfully()
    {
        var fileToEncrypt = Path.GetTempFileName();
        var encryptedFile = Path.GetTempFileName();
        var decryptedFile = Path.GetTempFileName();
        var password = _fixture.Create<string>();
        await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

        Assert.True(AesCryptProcessRunner.CanEncrypt(fileToEncrypt, encryptedFile, password));
        Assert.True(AesCryptProcessRunner.CanDecrypt(encryptedFile, decryptedFile, password));
    }

    // ──────────────────────────────────────────────────────────────
    // New positional syntax: -e -p <password> -o <output> <file>
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task PositionalSyntax_FileIsEncryptedSuccessfully()
    {
        var fileToEncrypt = Path.GetTempFileName();
        var encryptedFile = Path.GetTempFileName();
        var password = _fixture.Create<string>();
        await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

        Assert.True(AesCryptProcessRunner.CanEncryptPositional(fileToEncrypt, encryptedFile, password));
    }

    [Fact]
    public async Task PositionalSyntax_FileIsDecryptedSuccessfully()
    {
        var fileToEncrypt = Path.GetTempFileName();
        var encryptedFile = Path.GetTempFileName();
        var decryptedFile = Path.GetTempFileName();
        var password = _fixture.Create<string>();
        await CreateTextFile(fileToEncrypt, _fixture.Create<string>());

        Assert.True(AesCryptProcessRunner.CanEncryptPositional(fileToEncrypt, encryptedFile, password));
        Assert.True(AesCryptProcessRunner.CanDecryptPositional(encryptedFile, decryptedFile, password));
    }

    [Fact]
    public async Task PositionalSyntax_ProducesIdenticalOutputToLegacySyntax()
    {
        var plaintext = _fixture.Create<string>();
        var password = _fixture.Create<string>();

        var legacyInput = Path.GetTempFileName();
        var legacyEncrypted = Path.GetTempFileName();
        var legacyDecrypted = Path.GetTempFileName();

        var positionalInput = Path.GetTempFileName();
        var positionalEncrypted = Path.GetTempFileName();
        var positionalDecrypted = Path.GetTempFileName();

        await CreateTextFile(legacyInput, plaintext);
        await CreateTextFile(positionalInput, plaintext);

        Assert.True(AesCryptProcessRunner.CanEncrypt(legacyInput, legacyEncrypted, password));
        Assert.True(AesCryptProcessRunner.CanEncryptPositional(positionalInput, positionalEncrypted, password));

        Assert.True(AesCryptProcessRunner.CanDecrypt(legacyEncrypted, legacyDecrypted, password));
        Assert.True(AesCryptProcessRunner.CanDecryptPositional(positionalEncrypted, positionalDecrypted, password));

        Assert.Equal(await File.ReadAllTextAsync(legacyDecrypted), await File.ReadAllTextAsync(positionalDecrypted));
    }

    // ──────────────────────────────────────────────────────────────
    // Error cases
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void Error_NoOperationFlag_ReturnsNonZero()
    {
        var exitCode = AesCryptProcessRunner.RunArgs(["-p", "pass", "-o", "out.aes", "input.txt"]);
        Assert.NotEqual(0, exitCode);
    }

    [Fact]
    public void Error_NoPassword_ReturnsNonZero()
    {
        var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-o", "out.aes", "input.txt"]);
        Assert.NotEqual(0, exitCode);
    }

    [Fact]
    public void Error_NoInputFile_ReturnsNonZero()
    {
        var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", "pass", "-o", "out.aes"]);
        Assert.NotEqual(0, exitCode);
    }

    [Fact]
    public async Task Error_BothFlagAndPositionalFile_ReturnsNonZero()
    {
        var file = Path.GetTempFileName();
        await CreateTextFile(file, _fixture.Create<string>());

        var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", "pass", "-f", file, "-o", "out.aes", file]);
        Assert.NotEqual(0, exitCode);
    }

    [Fact]
    public void Error_InputFileNotFound_ReturnsNonZero()
    {
        var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", "pass", "-o", "out.aes", "file-that-does-not-exist.txt"]);
        Assert.NotEqual(0, exitCode);
    }

    private static async Task CreateTextFile(string path, string content)
    {
        await using var sw = File.CreateText(path);
        await sw.WriteLineAsync(content);
    }
}