namespace TRONSoft.TronAesCrypt.Core.Decryptors;

/// <summary>
/// Creates the appropriate <see cref="IAesDecryptor"/> for a given AES Crypt stream format version.
/// </summary>
internal static class AesDecryptorFactory
{
    /// <summary>
    /// Returns the <see cref="IAesDecryptor"/> implementation for the specified <paramref name="version"/>.
    /// </summary>
    /// <param name="version">The AES Crypt stream format version detected in the file header.</param>
    /// <returns>An <see cref="IAesDecryptor"/> that handles decryption for the given version.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when the version is not supported.</exception>
    internal static IAesDecryptor Create(AesCryptVersion version) => version switch
    {
        AesCryptVersion.V2 => new AesV2Decryptor(),
        AesCryptVersion.V3 => new AesV3Decryptor(),
        _ => throw new System.InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, (int)version))
    };
}