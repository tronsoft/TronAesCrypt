using System.IO;

namespace TRONSoft.TronAesCrypt.Core.Encryptors;

internal interface IAesEncryptor
{
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
    void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000);
}