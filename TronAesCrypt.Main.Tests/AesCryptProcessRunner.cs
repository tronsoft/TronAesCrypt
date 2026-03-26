using System;
using System.Collections.Generic;
using System.IO;
using TronAesCrypt.Main;
using TronAesCrypt.Main.Tests;

/// <summary>
/// Invokes the AesCrypt program entry point in-process for testing.
/// </summary>
public static class AesCryptProcessRunner
{
    public static bool CanEncrypt(string fileName, string outputFileName, string password) =>
        RunArgs(["-e", "-p", password, "-o", outputFileName, "-f", fileName]) == 0;

    public static bool CanDecrypt(string fileName, string outputFileName, string password) =>
        RunArgs(["-d", "-p", password, "-o", outputFileName, "-f", fileName]) == 0;

    public static bool CanEncryptPositional(string fileName, string outputFileName, string password) =>
        RunArgs(["-e", "-p", password, "-o", outputFileName, fileName]) == 0;

    public static bool CanDecryptPositional(string fileName, string outputFileName, string password) =>
        RunArgs(["-d", "-p", password, "-o", outputFileName, fileName]) == 0;

    public static bool CanEncryptWithKeyFile(string fileName, string outputFileName, string keyFile) =>
        RunArgs(["-e", "-k", keyFile, "-o", outputFileName, fileName]) == 0;

    public static bool CanDecryptWithKeyFile(string fileName, string outputFileName, string keyFile) =>
        RunArgs(["-d", "-k", keyFile, "-o", outputFileName, fileName]) == 0;

    public static int RunWithStreams(string[] args, Stream? stdinOverride, Stream? outputOverride)
    {
        var options = ParseArgs(args);
        var env = new TestEnvironment(stdinOverride, outputOverride, () => string.Empty);
        var runner = new CryptRunner(env);
        return runner.Run(options);
    }

    public static int RunWithPasswordReader(string[] args, Func<string> readPassword)
    {
        var options = ParseArgs(args);
        var env = new TestEnvironment(null, null, readPassword);
        var runner = new CryptRunner(env);
        return runner.Run(options);
    }

    private static Options ParseArgs(string[] args)
    {
        var knownValueFlags = new HashSet<string> { "-o", "-p", "-f", "-k" };
        var knownBoolFlags = new HashSet<string> { "-e", "-d", "-g" };
        var positionals = new List<string>();
        
        string? output = null;
        string? password = null;
        string? legacyFile = null;
        string? keyFile = null;

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "-o" && i + 1 < args.Length) { output = args[++i]; continue; }
            if (args[i] == "-p" && i + 1 < args.Length) { password = args[++i]; continue; }
            if (args[i] == "-f" && i + 1 < args.Length) { legacyFile = args[++i]; continue; }
            if (args[i] == "-k" && i + 1 < args.Length) { keyFile = args[++i]; continue; }

            if (!knownBoolFlags.Contains(args[i]) && !knownValueFlags.Contains(args[i]))
            {
                positionals.Add(args[i]);
            }
        }

        return new Options
        {
            Encrypt = Array.Exists(args, a => a == "-e"),
            Decrypt = Array.Exists(args, a => a == "-d"),
            Generate = Array.Exists(args, a => a == "-g"),
            Output = output,
            Password = password,
            LegacyFile = legacyFile,
            KeyFile = keyFile,
            Files = positionals,
        };
    }

    public static int RunArgs(string[] args)
    {
        var entryPoint = typeof(CryptRunner).Assembly.EntryPoint;
        if (entryPoint is null)
        {
            return 1;
        }

        return Convert.ToInt32(entryPoint.Invoke(null, [args]) ?? 1);
    }
}
