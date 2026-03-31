using System;
using System.IO;
using System.Threading.Tasks;
using CommandLine;

namespace TronAesCrypt.Main.Tests;

/// <summary>
/// Invokes the AesCrypt program entry point in-process for testing.
/// </summary>
public static class AesCryptProcessRunner
{
    public static async Task<bool> CanEncryptAsync(string fileName, string outputFileName, string password) =>
        await RunArgsAsync(["-e", "-p", password, "-o", outputFileName, "-f", fileName]) == 0;

    public static async Task<bool> CanDecryptAsync(string fileName, string outputFileName, string password) =>
        await RunArgsAsync(["-d", "-p", password, "-o", outputFileName, "-f", fileName]) == 0;

    public static async Task<bool> CanEncryptPositionalAsync(string fileName, string outputFileName, string password) =>
        await RunArgsAsync(["-e", "-p", password, "-o", outputFileName, fileName]) == 0;

    public static async Task<bool> CanDecryptPositionalAsync(string fileName, string outputFileName, string password) =>
        await RunArgsAsync(["-d", "-p", password, "-o", outputFileName, fileName]) == 0;

    public static async Task<bool> CanEncryptWithKeyFileAsync(string fileName, string outputFileName, string keyFile) =>
        await RunArgsAsync(["-e", "-k", keyFile, "-o", outputFileName, fileName]) == 0;

    public static async Task<bool> CanDecryptWithKeyFileAsync(string fileName, string outputFileName, string keyFile) =>
        await RunArgsAsync(["-d", "-k", keyFile, "-o", outputFileName, fileName]) == 0;

    public static async Task<int> RunWithStreamsAsync(string[] args, Stream? stdinOverride, Stream? outputOverride)
    {
        var parsedResult = Parser.Default.ParseArguments<Options>(args);
        if (parsedResult.Tag == ParserResultType.NotParsed) return 1;
        var options = ((Parsed<Options>)parsedResult).Value;

        var env = new TestEnvironment(stdinOverride, outputOverride, () => string.Empty);
        var runner = new CryptRunner(env);
        return await runner.RunAsync(options);
    }

    public static async Task<int> RunWithPasswordReaderAsync(string[] args, Func<string> readPassword)
    {
        var parsedResult = Parser.Default.ParseArguments<Options>(args);
        if (parsedResult.Tag == ParserResultType.NotParsed) return 1;
        var options = ((Parsed<Options>)parsedResult).Value;

        var env = new TestEnvironment(null, null, readPassword);
        var runner = new CryptRunner(env);
        return await runner.RunAsync(options);
    }

    public static async Task<int> RunArgsAsync(string[] args)
    {
        var parsedResult = Parser.Default.ParseArguments<Options>(args);
        if (parsedResult.Tag == ParserResultType.NotParsed) return 1;
        var options = ((Parsed<Options>)parsedResult).Value;

        var env = new TestEnvironment(null, null, () => string.Empty);
        var runner = new CryptRunner(env);
        return await runner.RunAsync(options);
    }
}
