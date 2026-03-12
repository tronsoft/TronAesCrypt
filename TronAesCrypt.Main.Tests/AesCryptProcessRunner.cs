using System;
using System.Reflection;

namespace TronAesCrypt.Main.Tests;

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

    public static int RunArgs(string[] args)
    {
        var entryPoint = typeof(Program).Assembly.EntryPoint;
        if (entryPoint is null)
        {
            return 1;
        }

        return Convert.ToInt32(entryPoint.Invoke(null, [args]) ?? 1);
    }
}