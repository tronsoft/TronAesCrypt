using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    // Phase 2: Auto-generated output filenames
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task AutoOutput_Encrypt_AppendsAesExtension()
    {
        var input = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.txt");
        var expectedOutput = input + ".aes";
        await CreateTextFile(input, _fixture.Create<string>());

        try
        {
            var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", "pass", input]);
            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(expectedOutput), $"Expected {expectedOutput} to exist");
        }
        finally
        {
            File.Delete(input);
            File.Delete(expectedOutput);
        }
    }

    [Fact]
    public async Task AutoOutput_Decrypt_RemovesAesExtension()
    {
        var baseName = Path.Combine(Path.GetTempPath(), _fixture.Create<string>());
        var plainInput = baseName + ".txt";
        var encrypted = baseName + ".txt.aes";
        var expectedDecrypted = baseName + ".txt";

        await CreateTextFile(plainInput, _fixture.Create<string>());

        try
        {
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-e", "-p", "pass", "-o", encrypted, plainInput]));

            File.Delete(plainInput);

            var exitCode = AesCryptProcessRunner.RunArgs(["-d", "-p", "pass", encrypted]);
            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(expectedDecrypted), $"Expected {expectedDecrypted} to exist");
        }
        finally
        {
            File.Delete(plainInput);
            File.Delete(encrypted);
        }
    }

    [Fact]
    public void AutoOutput_Decrypt_NonAesFile_ReturnsNonZero()
    {
        var input = Path.GetTempFileName();
        var exitCode = AesCryptProcessRunner.RunArgs(["-d", "-p", "pass", input]);
        Assert.NotEqual(0, exitCode);
    }

    // ──────────────────────────────────────────────────────────────
    // Phase 2: Interactive password prompt (injected via Func<string>)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task InteractivePrompt_UsedWhenNoPFlagSupplied()
    {
        var input = Path.GetTempFileName();
        var encrypted = Path.GetTempFileName();
        var decrypted = Path.GetTempFileName();
        var password = _fixture.Create<string>();
        var content = _fixture.Create<string>();
        await CreateTextFile(input, content);

        var encryptExit = AesCryptProcessRunner.RunWithPasswordReader(
            ["-e", "-o", encrypted, input],
            () => password);
        Assert.Equal(0, encryptExit);

        var decryptExit = AesCryptProcessRunner.RunWithPasswordReader(
            ["-d", "-o", decrypted, encrypted],
            () => password);
        Assert.Equal(0, decryptExit);

        Assert.Equal(content + Environment.NewLine, await File.ReadAllTextAsync(decrypted));
    }

    [Fact]
    public async Task InteractivePrompt_WrongPasswordFails()
    {
        var input = Path.GetTempFileName();
        var encrypted = Path.GetTempFileName();
        var decrypted = Path.GetTempFileName();
        await CreateTextFile(input, _fixture.Create<string>());

        AesCryptProcessRunner.RunWithPasswordReader(["-e", "-o", encrypted, input], () => "correctpassword");

        var decryptExit = AesCryptProcessRunner.RunWithPasswordReader(
            ["-d", "-o", decrypted, encrypted],
            () => "wrongpassword");
        Assert.NotEqual(0, decryptExit);
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
    public async Task NoPasswordFlag_InvokesPasswordReader()
    {
        var input = Path.GetTempFileName();
        var output = Path.GetTempFileName();
        await CreateTextFile(input, _fixture.Create<string>());

        var readerCalled = false;
        var exitCode = AesCryptProcessRunner.RunWithPasswordReader(
            ["-e", "-o", output, input],
            () =>
            {
                readerCalled = true;
                return "anypassword";
            });

        Assert.Equal(0, exitCode);
        Assert.True(readerCalled, "Password reader should have been invoked when -p is absent");
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

    // ──────────────────────────────────────────────────────────────
    // Phase 3: stdin/stdout piping (tested via stream injection)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void Piping_EncryptFromStdin_ToStdout_RoundTrips()
    {
        var plaintext = "Hello, piped world!"u8.ToArray();
        var password = _fixture.Create<string>();

        var encryptedStream = new MemoryStream();
        var decryptedStream = new MemoryStream();

        AesCryptProcessRunner.RunWithStreams(
            ["-e", "-p", password, "-o", "-", "-"],
            new MemoryStream(plaintext),
            encryptedStream);

        encryptedStream.Position = 0;

        AesCryptProcessRunner.RunWithStreams(
            ["-d", "-p", password, "-o", "-", "-"],
            encryptedStream,
            decryptedStream);

        Assert.Equal(plaintext, decryptedStream.ToArray());
    }

    [Fact]
    public void Piping_EncryptFromStdin_ToFile_RoundTrips()
    {
        var plaintext = "Piped to file!"u8.ToArray();
        var password = _fixture.Create<string>();
        var encryptedFile = Path.GetTempFileName();
        var decryptedFile = Path.GetTempFileName();

        try
        {
            AesCryptProcessRunner.RunWithStreams(
                ["-e", "-p", password, "-o", encryptedFile, "-"],
                new MemoryStream(plaintext),
                outputOverride: null);

            AesCryptProcessRunner.RunWithStreams(
                ["-d", "-p", password, "-o", decryptedFile, "-"],
                new MemoryStream(File.ReadAllBytes(encryptedFile)),
                outputOverride: null);

            Assert.Equal(plaintext, File.ReadAllBytes(decryptedFile));
        }
        finally
        {
            File.Delete(encryptedFile);
            File.Delete(decryptedFile);
        }
    }

    [Fact]
    public async Task Piping_EncryptFile_OutputToStdout_ProducesValidCiphertext()
    {
        var input = Path.GetTempFileName();
        var content = _fixture.Create<string>();
        await CreateTextFile(input, content);
        var password = _fixture.Create<string>();
        var decryptedStream = new MemoryStream();
        var encryptedStream = new MemoryStream();

        try
        {
            AesCryptProcessRunner.RunWithStreams(
                ["-e", "-p", password, "-o", "-", input],
                stdinOverride: null,
                encryptedStream);

            encryptedStream.Position = 0;

            AesCryptProcessRunner.RunWithStreams(
                ["-d", "-p", password, "-o", "-", "-"],
                encryptedStream,
                decryptedStream);

            var decryptedText = System.Text.Encoding.UTF8.GetString(decryptedStream.ToArray());
            Assert.Contains(content, decryptedText);
        }
        finally
        {
            File.Delete(input);
        }
    }

    [Fact]
    public void Piping_StdinWithoutExplicitOutput_ReturnsNonZero()
    {
        var exitCode = AesCryptProcessRunner.RunWithPasswordReader(
            ["-e", "-p", "pass", "-"],
            () => "pass");
        Assert.NotEqual(0, exitCode);
    }

    // ──────────────────────────────────────────────────────────────
    // Phase 4: Key file generation and usage (-g -k / -k)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void KeyFile_Generate_CreatesUtf16LeFileWithMinLength()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.key");

        try
        {
            var exitCode = AesCryptProcessRunner.RunArgs(["-g", "-k", keyFile]);

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(keyFile), "Key file should have been created");

            var bytes = File.ReadAllBytes(keyFile);
            Assert.True(bytes.Length >= 2, "Key file should contain at least the BOM");
            Assert.Equal(0xFF, bytes[0]);
            Assert.Equal(0xFE, bytes[1]);

            var content = System.Text.Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
            Assert.True(content.Length >= 32, $"Key file content should be at least 32 chars, got {content.Length}");
        }
        finally
        {
            File.Delete(keyFile);
        }
    }

    [Fact]
    public void KeyFile_Generate_WithoutKFlag_ReturnsNonZero()
    {
        var exitCode = AesCryptProcessRunner.RunArgs(["-g"]);
        Assert.NotEqual(0, exitCode);
    }

    [Fact]
    public void KeyFile_Generate_ExistingFile_ReturnsNonZero()
    {
        var keyFile = Path.GetTempFileName();

        try
        {
            var exitCode = AesCryptProcessRunner.RunArgs(["-g", "-k", keyFile]);
            Assert.NotEqual(0, exitCode);
        }
        finally
        {
            File.Delete(keyFile);
        }
    }

    [Fact]
    public async Task KeyFile_EncryptDecrypt_RoundTrip()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.key");
        var input = Path.GetTempFileName();
        var encrypted = Path.GetTempFileName();
        var decrypted = Path.GetTempFileName();
        var content = _fixture.Create<string>();
        await CreateTextFile(input, content);

        try
        {
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-g", "-k", keyFile]));
            Assert.True(AesCryptProcessRunner.CanEncryptWithKeyFile(input, encrypted, keyFile));
            Assert.True(AesCryptProcessRunner.CanDecryptWithKeyFile(encrypted, decrypted, keyFile));

            Assert.Equal(content + Environment.NewLine, await File.ReadAllTextAsync(decrypted));
        }
        finally
        {
            File.Delete(keyFile);
            File.Delete(input);
            File.Delete(encrypted);
            File.Delete(decrypted);
        }
    }

    [Fact]
    public async Task KeyFile_Usage_BothPasswordAndKeyFile_ReturnsNonZero()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.key");
        var input = Path.GetTempFileName();
        await CreateTextFile(input, _fixture.Create<string>());

        try
        {
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-g", "-k", keyFile]));

            var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", "somepassword", "-k", keyFile, "-o", "out.aes", input]);
            Assert.NotEqual(0, exitCode);
        }
        finally
        {
            File.Delete(keyFile);
            File.Delete(input);
        }
    }

    [Fact]
    public void KeyFile_Usage_MissingKeyFile_ReturnsNonZero()
    {
        var input = Path.GetTempFileName();

        try
        {
            var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-k", "nonexistent.key", "-o", "out.aes", input]);
            Assert.NotEqual(0, exitCode);
        }
        finally
        {
            File.Delete(input);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Phase 5: Multiple file support
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task MultiFile_EncryptDecrypt_AllFilesProcessed()
    {
        var password = _fixture.Create<string>();
        var files = new[]
        {
            (plain: Path.GetTempFileName(), encrypted: "", decrypted: Path.GetTempFileName()),
            (plain: Path.GetTempFileName(), encrypted: "", decrypted: Path.GetTempFileName()),
            (plain: Path.GetTempFileName(), encrypted: "", decrypted: Path.GetTempFileName()),
        };

        for (var i = 0; i < files.Length; i++)
        {
            await CreateTextFile(files[i].plain, _fixture.Create<string>());
            files[i].encrypted = files[i].plain + ".aes";
        }

        try
        {
            var encryptArgs = new List<string> { "-e", "-p", password };
            foreach (var f in files)
            {
                encryptArgs.Add(f.plain);
            }

            Assert.Equal(0, AesCryptProcessRunner.RunArgs([.. encryptArgs]));

            foreach (var f in files)
            {
                Assert.True(File.Exists(f.encrypted), $"Expected {f.encrypted} to exist");
            }

            foreach (var f in files)
            {
                Assert.True(AesCryptProcessRunner.CanDecrypt(f.encrypted, f.decrypted, password));
                Assert.Equal(
                    await File.ReadAllTextAsync(f.plain),
                    await File.ReadAllTextAsync(f.decrypted));
            }
        }
        finally
        {
            foreach (var f in files)
            {
                File.Delete(f.plain);
                File.Delete(f.encrypted);
                File.Delete(f.decrypted);
            }
        }
    }

    [Fact]
    public async Task MultiFile_OneMissingFile_OthersStillProcessed()
    {
        var password = _fixture.Create<string>();
        var goodFile = Path.GetTempFileName();
        var goodEncrypted = goodFile + ".aes";
        var missingFile = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}_missing.txt");

        await CreateTextFile(goodFile, _fixture.Create<string>());

        try
        {
            var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", password, goodFile, missingFile]);

            Assert.NotEqual(0, exitCode);
            Assert.True(File.Exists(goodEncrypted), "Good file should have been encrypted even though another failed");
        }
        finally
        {
            File.Delete(goodFile);
            File.Delete(goodEncrypted);
        }
    }

    [Fact]
    public async Task MultiFile_WithOutputFlag_ReturnsNonZero()
    {
        var file1 = Path.GetTempFileName();
        var file2 = Path.GetTempFileName();
        await CreateTextFile(file1, _fixture.Create<string>());
        await CreateTextFile(file2, _fixture.Create<string>());

        try
        {
            var exitCode = AesCryptProcessRunner.RunArgs(["-e", "-p", "pass", "-o", "combined.aes", file1, file2]);
            Assert.NotEqual(0, exitCode);
        }
        finally
        {
            File.Delete(file1);
            File.Delete(file2);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Phase 6: Integration & backward compatibility validation
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Integration_LegacySyntax_AllFlagsExplicit_StillWorks()
    {
        var input = Path.GetTempFileName();
        var encrypted = Path.GetTempFileName();
        var decrypted = Path.GetTempFileName();
        var content = _fixture.Create<string>();
        var password = _fixture.Create<string>();
        await CreateTextFile(input, content);

        try
        {
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-e", "-f", input, "-o", encrypted, "-p", password]));
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-d", "-f", encrypted, "-o", decrypted, "-p", password]));
            Assert.Equal(content + Environment.NewLine, await File.ReadAllTextAsync(decrypted));
        }
        finally
        {
            File.Delete(input);
            File.Delete(encrypted);
            File.Delete(decrypted);
        }
    }

    [Fact]
    public async Task Integration_MultipleFiles_WithKeyFile_AutoOutput()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.key");
        var files = new[]
        {
            Path.GetTempFileName(),
            Path.GetTempFileName(),
        };
        var contents = new[] { _fixture.Create<string>(), _fixture.Create<string>() };

        for (var i = 0; i < files.Length; i++)
        {
            await CreateTextFile(files[i], contents[i]);
        }

        try
        {
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-g", "-k", keyFile]));

            var encryptArgs = new[] { "-e", "-k", keyFile }.Concat(files).ToArray();
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(encryptArgs));

            for (var i = 0; i < files.Length; i++)
            {
                var encryptedPath = files[i] + ".aes";
                Assert.True(File.Exists(encryptedPath));

                var decrypted = Path.GetTempFileName();
                try
                {
                    Assert.True(AesCryptProcessRunner.CanDecryptWithKeyFile(encryptedPath, decrypted, keyFile));
                    Assert.Equal(contents[i] + Environment.NewLine, await File.ReadAllTextAsync(decrypted));
                }
                finally
                {
                    File.Delete(encryptedPath);
                    File.Delete(decrypted);
                }
            }
        }
        finally
        {
            File.Delete(keyFile);
            foreach (var f in files)
            {
                File.Delete(f);
            }
        }
    }

    [Fact]
    public void Integration_StdinToStdout_WithKeyFile_RoundTrips()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.key");
        var plaintext = "stdin+keyfile integration test"u8.ToArray();

        try
        {
            Assert.Equal(0, AesCryptProcessRunner.RunArgs(["-g", "-k", keyFile]));

            var encrypted = new MemoryStream();
            AesCryptProcessRunner.RunWithStreams(
                ["-e", "-k", keyFile, "-o", "-", "-"],
                new MemoryStream(plaintext),
                encrypted);

            encrypted.Position = 0;

            var decrypted = new MemoryStream();
            AesCryptProcessRunner.RunWithStreams(
                ["-d", "-k", keyFile, "-o", "-", "-"],
                encrypted,
                decrypted);

            Assert.Equal(plaintext, decrypted.ToArray());
        }
        finally
        {
            File.Delete(keyFile);
        }
    }

    [Fact]
    public void Integration_LargeFileViaStdinBuffering_RoundTrips()
    {
        var password = _fixture.Create<string>();
        var random = new Random(42);
        var plaintext = new byte[1024 * 1024];
        random.NextBytes(plaintext);

        var encrypted = new MemoryStream();
        AesCryptProcessRunner.RunWithStreams(
            ["-e", "-p", password, "-o", "-", "-"],
            new MemoryStream(plaintext),
            encrypted);

        encrypted.Position = 0;

        var decrypted = new MemoryStream();
        AesCryptProcessRunner.RunWithStreams(
            ["-d", "-p", password, "-o", "-", "-"],
            encrypted,
            decrypted);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Integration_PositionalArgs_AutoOutput_InteractivePrompt_Combined()
    {
        var input = Path.Combine(Path.GetTempPath(), $"{_fixture.Create<string>()}.txt");
        var expectedEncrypted = input + ".aes";
        var password = _fixture.Create<string>();
        var content = _fixture.Create<string>();
        await CreateTextFile(input, content);

        try
        {
            var encryptExit = AesCryptProcessRunner.RunWithPasswordReader(["-e", input], () => password);
            Assert.Equal(0, encryptExit);
            Assert.True(File.Exists(expectedEncrypted));

            File.Delete(input);

            var decryptExit = AesCryptProcessRunner.RunWithPasswordReader(["-d", expectedEncrypted], () => password);
            Assert.Equal(0, decryptExit);
            Assert.True(File.Exists(input));
            Assert.Equal(content + Environment.NewLine, await File.ReadAllTextAsync(input));
        }
        finally
        {
            File.Delete(input);
            File.Delete(expectedEncrypted);
        }
    }

    private static async Task CreateTextFile(string path, string content)
    {
        await using var sw = File.CreateText(path);
        await sw.WriteLineAsync(content);
    }
}