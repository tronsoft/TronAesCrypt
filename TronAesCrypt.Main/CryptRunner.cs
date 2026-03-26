using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using TRONSoft.TronAesCrypt.Core;

namespace TronAesCrypt.Main;

public class CryptRunner(ICryptEnvironment env)
{
    private const int BufferSize = 64 * 1024;
    private readonly PasswordResolver _passwordResolver = new(env);

    public async Task<int> RunAsync(Options options)
    {
        try
        {
            ValidateOptions(options);
        }
        catch (ArgumentException ex)
        {
            env.WriteError(ex.Message);
            return 1;
        }

        if (options.Generate)
        {
            return await RunGenerateAsync(options);
        }

        IEnumerable<string> files;
        string password;
        try
        {
            files = options.ResolveInputFiles();
            password = _passwordResolver.Resolve(options);
        }
        catch (Exception ex)
        {
            env.WriteError(ex.Message);
            return 1;
        }

        if (options.Encrypt || options.Decrypt)
        {
            return await RunCryptAsync(options, files, password);
        }

        env.WriteError(Resources.You_must_specify_either_encrypt_or_decrypt_option);
        return 1;
    }

    private static void ValidateOptions(Options options) => OptionsValidator.ValidateOrThrow(options);

    private async Task<int> RunGenerateAsync(Options options)
    {
        if (File.Exists(options.KeyFile))
        {
            env.WriteError(string.Format(Resources.Key_file_already_exists, options.KeyFile));
            return 1;
        }

        try
        {
            await GenerateKeyFileAsync(options.KeyFile!);
            env.WriteInfo(string.Format(Resources.Key_file_generated, options.KeyFile));
            return 0;
        }
        catch (Exception ex)
        {
            env.WriteError(ex.Message);
            return 1;
        }
    }

    private async Task<int> RunCryptAsync(Options options, IEnumerable<string> files, string password)
    {
        var fileList = files.ToList();
        var anyFailed = false;

        foreach (var inputFile in fileList)
        {
            try
            {
                if (options.Encrypt)
                {
                    await EncryptFileAsync(inputFile, options.Output, password);
                }
                else
                {
                    await DecryptFileAsync(inputFile, options.Output, password);
                }
            }
            catch (Exception ex)
            {
                env.WriteError(ex.Message);
                anyFailed = true;
            }
        }

        return anyFailed ? 1 : 0;
    }

    private async Task EncryptFileAsync(string inputFile, string? outputPath, string password)
    {
        var isStdin = inputFile == "-";
        var isStdout = outputPath == "-";
        var outputFile = outputPath ?? (inputFile + ".aes");

        if (!isStdin && !File.Exists(inputFile))
        {
            throw new FileNotFoundException(string.Format(Resources.The_input_file_does_not_exist, inputFile));
        }

        using var inStream = env.OpenInput(inputFile, isStdin);
        using var outStream = env.OpenOutput(outputFile, isStdout);
        await new AesCrypt().EncryptStreamAsync(inStream, outStream, password, BufferSize);
    }

    private async Task DecryptFileAsync(string inputFile, string? outputPath, string password)
    {
        var isStdin = inputFile == "-";
        var isStdout = outputPath == "-";
        var outputFile = outputPath ?? inputFile.GetDecryptOutputPath();

        if (!isStdin && !File.Exists(inputFile))
        {
            throw new FileNotFoundException(string.Format(Resources.The_input_file_does_not_exist, inputFile));
        }

        if (isStdin)
        {
            await DecryptFromStdinAsync(outputFile, isStdout, password);
            return;
        }

        using var inStream = env.OpenInput(inputFile, false);
        using var outStream = env.OpenOutput(outputFile, isStdout);

        if (inStream.CanSeek)
        {
            await new AesCrypt().DecryptStreamAsync(inStream, outStream, password, BufferSize);
            return;
        }

        using var seekableInput = await EnsureSeekableAsync(inStream);
        await new AesCrypt().DecryptStreamAsync(seekableInput, outStream, password, BufferSize);
    }

    private async Task DecryptFromStdinAsync(string outputFile, bool isStdout, string password)
    {
        string? tempFile = null;
        try
        {
            try
            {
                tempFile = Path.Combine(
                    Path.GetTempPath(),
                    $"TronAesCrypt_stdin_{Guid.NewGuid():N}.aes.tmp");

                using var tempStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write);
                using var stdin = env.OpenInput("-", true);
                await stdin.CopyToAsync(tempStream);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
            {
                env.WriteInfo(Resources.Stdin_using_memory_fallback);
                using var stdin = env.OpenInput("-", true);
                using var bufferedStream = await EnsureSeekableAsync(stdin);
                using var fallbackOutStream = env.OpenOutput(outputFile, isStdout);
                await new AesCrypt().DecryptStreamAsync(bufferedStream, fallbackOutStream, password, BufferSize);
                return;
            }

            using var inStream = env.OpenInput(tempFile, false);
            using var finalOutStream = env.OpenOutput(outputFile, isStdout);
            await new AesCrypt().DecryptStreamAsync(inStream, finalOutStream, password, BufferSize);
        }
        finally
        {
            if (tempFile != null && File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { /* best effort */ }
            }
        }
    }

    private static async Task<Stream> EnsureSeekableAsync(Stream stream)
    {
        if (stream.CanSeek)
        {
            return stream;
        }

        var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer);
        buffer.Position = 0;
        return buffer;
    }

    private async Task GenerateKeyFileAsync(string path)
    {
        using var stream = env.OpenOutput(path, false);
        await using var writer = new StreamWriter(stream, new System.Text.UnicodeEncoding(false, true));

        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        var key = new char[64];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
        }
        await writer.WriteAsync(key);
    }
}
