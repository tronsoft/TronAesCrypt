using System.IO;

namespace TRONSoft.TronAesCrypt.Core.Decryptors;

/// <summary>
/// Defines the contract for AES Crypt stream format decryptors (v2 and v3).
/// </summary>
internal interface IAesDecryptor
{
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
    void DecryptStream(Stream inStream, Stream outStream, string password, int bufferSize);

    /// <summary>
    /// Decrypt the stream asynchronously. Automatically detects and supports both v2 and v3 stream formats.
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
    /// <param name="cancellationToken">A token to cancel the operation.</param>
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
    System.Threading.Tasks.Task DecryptStreamAsync(Stream inStream, Stream outStream, string password, int bufferSize, System.Threading.CancellationToken cancellationToken = default);
}
