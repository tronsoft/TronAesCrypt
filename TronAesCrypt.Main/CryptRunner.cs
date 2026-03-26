using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using TRONSoft.TronAesCrypt.Core;

namespace TronAesCrypt.Main;

public class CryptRunner(ICryptEnvironment env)
{
    private const int BufferSize = 64 * 1024;
    private readonly PasswordResolver _passwordResolver = new(env);

    public int Run(Options options)
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
            return RunGenerate(options);
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
            return RunCrypt(options, files, password);
        }

        env.WriteError(Resources.You_must_specify_either_encrypt_or_decrypt_option);
        return 1;
    }

    private static void ValidateOptions(Options options) => OptionsValidator.ValidateOrThrow(options);

    private int RunGenerate(Options options)
    {
        if (File.Exists(options.KeyFile))
        {
            env.WriteError(string.Format(Resources.Key_file_already_exists, options.KeyFile));
            return 1;
        }

        try
        {
            GenerateKeyFile(options.KeyFile!);
            env.WriteInfo(string.Format(Resources.Key_file_generated, options.KeyFile));
            return 0;
        }
        catch (Exception ex)
        {
            env.WriteError(ex.Message);
            return 1;
        }
    }

    private int RunCrypt(Options options, IEnumerable<string> files, string password)
    {
        var fileList = files.ToList();
        var anyFailed = false;

        foreach (var inputFile in fileList)
        {
            try
            {
                if (options.Encrypt)
                {
                    EncryptFile(inputFile, options.Output, password);
                }
                else
                {
                    DecryptFile(inputFile, options.Output, password);
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

    private void EncryptFile(string inputFile, string? outputPath, string password)
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
        new AesCrypt().EncryptStream(inStream, outStream, password, BufferSize);
    }

    private void DecryptFile(string inputFile, string? outputPath, string password)
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
            DecryptFromStdin(outputFile, isStdout, password);
            return;
        }

        using var inStream = env.OpenInput(inputFile, false);
        using var outStream = env.OpenOutput(outputFile, isStdout);

        if (inStream.CanSeek)
        {
            new AesCrypt().DecryptStream(inStream, outStream, password, BufferSize);
            return;
        }

        using var seekableInput = EnsureSeekable(inStream);
        new AesCrypt().DecryptStream(seekableInput, outStream, password, BufferSize);
    }

    private void DecryptFromStdin(string outputFile, bool isStdout, string password)
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
                stdin.CopyTo(tempStream);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
            {
                env.WriteInfo(Resources.Stdin_using_memory_fallback);
                using var stdin = env.OpenInput("-", true);
                using var bufferedStream = EnsureSeekable(stdin);
                using var fallbackOutStream = env.OpenOutput(outputFile, isStdout);
                new AesCrypt().DecryptStream(bufferedStream, fallbackOutStream, password, BufferSize);
                return;
            }

            using var inStream = env.OpenInput(tempFile, false);
            using var finalOutStream = env.OpenOutput(outputFile, isStdout);
            new AesCrypt().DecryptStream(inStream, finalOutStream, password, BufferSize);
        }
        finally
        {
            if (tempFile != null && File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { /* best effort */ }
            }
        }
    }

    private static Stream EnsureSeekable(Stream stream)
    {
        if (stream.CanSeek)
        {
            return stream;
        }

        var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        buffer.Position = 0;
        return buffer;
    }

    private void GenerateKeyFile(string path)
    {
        using var stream = env.OpenOutput(path, false);
        using var writer = new StreamWriter(stream, new System.Text.UnicodeEncoding(false, true));

        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        var key = new char[64];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
        }
        writer.Write(key);
    }
}
