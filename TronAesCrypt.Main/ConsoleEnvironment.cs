using System;
using System.IO;

namespace TronAesCrypt.Main;

public class ConsoleEnvironment(Func<string> readPassword) : ICryptEnvironment
{
    public Stream OpenInput(string path, bool isStdin)
    {
        if (!isStdin)
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read);
        }

        return Console.OpenStandardInput();
    }

    public Stream OpenOutput(string path, bool isStdout)
    {
        if (isStdout)
        {
            return Console.OpenStandardOutput();
        }

        return new FileStream(path, FileMode.Create, FileAccess.Write);
    }

    public string ReadPassword() => readPassword();

    public void WriteError(string message) => Console.WriteLine(message);

    public void WriteInfo(string message) => Console.WriteLine(message);
}