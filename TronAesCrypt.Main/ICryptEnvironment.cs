using System;
using System.IO;

namespace TronAesCrypt.Main;

/// <summary>
/// Abstraction for environmental interactions (Console, File System) to enable testability.
/// </summary>
public interface ICryptEnvironment
{
    Stream OpenInput(string path, bool isStdin);
    Stream OpenOutput(string path, bool isStdout);
    string ReadPassword();
    void WriteError(string message);
    void WriteInfo(string message);
}