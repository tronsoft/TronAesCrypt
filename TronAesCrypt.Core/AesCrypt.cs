using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TRONSoft.TronAesCrypt.Core.Decryptors;
using TRONSoft.TronAesCrypt.Core.Encryptors;

namespace TRONSoft.TronAesCrypt.Core;

public class AesCrypt : IAesDecryptor, IAesEncryptor
{
    private const int AesBlockSize = 16;
    private const int MaxPassLen = 1024;

    private readonly AesCryptHeader _aesCryptHeader = new();

    public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024, int kdfIterations = 300_000)
    {
        using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write);
        EncryptStream(inputStream, outputStream, password, bufferSize, kdfIterations);
    }

    public async Task EncryptFileAsync(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024, int kdfIterations = 300_000, CancellationToken cancellationToken = default)
    {
        await using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, useAsync: true);
        await using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, useAsync: true);
        await EncryptStreamAsync(inputStream, outputStream, password, bufferSize, kdfIterations, cancellationToken).ConfigureAwait(false);
    }

    public void DecryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024)
    {
        using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write);
        DecryptStream(inputStream, outputStream, password, bufferSize);
    }

    public async Task DecryptFileAsync(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024, CancellationToken cancellationToken = default)
    {
        await using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, useAsync: true);
        await using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, useAsync: true);
        await DecryptStreamAsync(inputStream, outputStream, password, bufferSize, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public void DecryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
    {
        ArgumentNullException.ThrowIfNull(inStream);
        ArgumentNullException.ThrowIfNull(outStream);
        ArgumentNullException.ThrowIfNull(password);

        if (bufferSize % AesBlockSize != 0)
        {
            throw new ArgumentException("Buffer size must be a multiple of AES block size.");
        }

        if (password.Length > MaxPassLen)
        {
            throw new ArgumentException("The password is too long.");
        }

        if (!inStream.CanSeek)
        {
            throw new ArgumentException(
                "Input stream must be seekable for decryption (v2/v3 format requires reading file header and trailer).",
                nameof(inStream));
        }

        var version = _aesCryptHeader.PeekAesCryptVersion(inStream);
        var decryptor = AesDecryptorFactory.Create(version);
        decryptor.DecryptStream(inStream, outStream, password, bufferSize);
    }

    /// <inheritdoc />
    public async Task DecryptStreamAsync(Stream inStream, Stream outStream, string password, int bufferSize, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inStream);
        ArgumentNullException.ThrowIfNull(outStream);
        ArgumentNullException.ThrowIfNull(password);

        if (bufferSize % AesBlockSize != 0)
        {
            throw new ArgumentException("Buffer size must be a multiple of AES block size.");
        }

        if (password.Length > MaxPassLen)
        {
            throw new ArgumentException("The password is too long.");
        }

        if (!inStream.CanSeek)
        {
            throw new ArgumentException(
                "Input stream must be seekable for decryption (v2/v3 format requires reading file header and trailer).",
                nameof(inStream));
        }

        var version = await _aesCryptHeader.PeekAesCryptVersionAsync(inStream, cancellationToken).ConfigureAwait(false);
        var decryptor = AesDecryptorFactory.Create(version);
        await decryptor.DecryptStreamAsync(inStream, outStream, password, bufferSize, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000) =>
        new AesV3Encryptor().EncryptStream(inStream, outStream, password, bufferSize, kdfIterations);

    /// <inheritdoc />
    public Task EncryptStreamAsync(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000, CancellationToken cancellationToken = default) =>
        new AesV3Encryptor().EncryptStreamAsync(inStream, outStream, password, bufferSize, kdfIterations, cancellationToken);
}
