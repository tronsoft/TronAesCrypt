using System.IO;

namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Defines the contract for AES Crypt stream format decryptors (v2 and v3).
/// </summary>
internal interface IAesDecryptor
{
    /// <summary>
    /// Decrypts the ciphertext from <paramref name="inStream"/> and writes the plaintext to <paramref name="outStream"/>.
    /// </summary>
    /// <param name="inStream">Seekable input stream positioned at the start of the ciphertext.</param>
    /// <param name="outStream">Output stream for the decrypted plaintext.</param>
    /// <param name="internalKey">The 32-byte session key used to decrypt the data.</param>
    /// <param name="dataIv">The 16-byte IV used to decrypt the data.</param>
    /// <param name="bufferSize">Buffer size in bytes; must be a multiple of 16 (AES block size).</param>
    void Decrypt(Stream inStream, Stream outStream, byte[] internalKey, byte[] dataIv, int bufferSize);
}
