using System;
using System.IO;

namespace TronAesCrypt.Main.Tests;

/// <summary>
/// Test implementation of ICryptEnvironment.
/// Allows injection of stdin/stdout streams and password reader for testing.
/// </summary>
public class TestEnvironment : ICryptEnvironment
{
    private readonly Stream? _stdinOverride;
    private readonly Stream? _stdoutOverride;
    private readonly Func<string> _passwordReader;

    public TestEnvironment(Stream? stdinOverride = null, Stream? stdoutOverride = null, Func<string>? passwordReader = null)
    {
        _stdinOverride = stdinOverride;
        _stdoutOverride = stdoutOverride;
        _passwordReader = passwordReader ?? (() => string.Empty);
    }

    /// <summary>
    /// Opens an input stream. Returns the stdin override directly for stdin paths.
    /// Seekability for decryption is handled by the caller (CryptRunner.EnsureSeekable).
    /// </summary>
    public Stream OpenInput(string path, bool isStdin)
    {
        if (!isStdin)
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read);
        }

        if (_stdinOverride == null)
        {
            throw new InvalidOperationException("No stdin override provided in TestEnvironment");
        }

        return new NonDisposingStream(_stdinOverride);
    }

    /// <summary>
    /// Opens an output stream.
    /// </summary>
    public Stream OpenOutput(string path, bool isStdout)
    {
        if (isStdout)
        {
            if (_stdoutOverride == null)
            {
                throw new InvalidOperationException("No stdout override provided in TestEnvironment");
            }

            return new NonDisposingStream(_stdoutOverride);
        }

        return new FileStream(path, FileMode.Create, FileAccess.Write);
    }

    /// <summary>
    /// Reads a password using the injected reader function.
    /// </summary>
    public string ReadPassword() => _passwordReader();

    /// <summary>
    /// Writes an error message (discarded in tests by default).
    /// </summary>
    public void WriteError(string message)
    {
        // In tests, we typically don't care about error output
    }

    /// <summary>
    /// Writes an informational message (discarded in tests by default).
    /// </summary>
    public void WriteInfo(string message)
    {
        // In tests, we typically don't care about info output
    }
}
