using System;
using System.IO;
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

    public void DecryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024)
    {
        using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write);
        DecryptStream(inputStream, outputStream, password, bufferSize);
    }

    /// <summary>
    /// Decrypt the stream. Automatically detects and supports both v2 and v3 stream formats.
    /// </summary>
    /// <param name="inStream">The input stream.</param>
    /// <param name="outStream">The output stream for decrypted data</param>
    /// <param name="password">The password to use for decrypting.</param>
    /// <param name="bufferSize">
    ///     bufferSize: decryption buffer size, must be a multiple of
    ///     AES block size (16)
    ///     using a larger buffer speeds up things when dealing
    ///     with big files
    /// </param>
    /// <remarks>
    /// The input stream must be seekable because the AES Crypt format requires:
    /// 1. Reading the file header first to determine the version (v2 or v3) and iteration count
    /// 2. Seeking to the trailer at the end of the file to verify the HMAC after decryption
    /// Non-seekable streams (e.g., network streams, pipes) are not supported for decryption.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    ///     Thrown when the file is corrupt, the password is incorrect, or the stream format is unsupported.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Thrown when the input stream is not seekable.
    /// </exception>
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
                @"Input stream must be seekable for decryption (v2/v3 format requires reading file header and trailer).",
                nameof(inStream));
        }

        var version = _aesCryptHeader.PeekAesCryptVersion(inStream);
        var decryptor = AesDecryptorFactory.Create(version);
        decryptor.DecryptStream(inStream, outStream, password, bufferSize);
    }

    /// <summary>
    /// Encrypt the stream using AES Crypt v3 format with PBKDF2-HMAC-SHA512 key derivation.
    /// </summary>
    /// <param name="inStream">The input stream.</param>
    /// <param name="outStream">The aes crypt output stream</param>
    /// <param name="password">The password to use for encrypting.</param>
    /// <param name="bufferSize">
    ///     bufferSize: encryption buffer size, must be a multiple of
    ///     AES block size (16)
    ///     using a larger buffer speeds up things when dealing
    ///     with big files
    /// </param>
    /// <param name="kdfIterations">
    ///     The number of PBKDF2-HMAC-SHA512 iterations for key derivation (default: 300,000).
    ///     Higher values provide better security against brute-force attacks but increase processing time.
    /// </param>
    public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000) =>
        new AesV3Encryptor().EncryptStream(inStream, outStream, password, bufferSize, kdfIterations);
}