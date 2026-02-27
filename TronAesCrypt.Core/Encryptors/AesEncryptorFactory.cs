using System;

namespace TRONSoft.TronAesCrypt.Core.Encryptors;

/// <summary>
/// Creates the appropriate <see cref="IAesEncryptor"/> for a given AES Crypt stream format version.
/// </summary>
internal static class AesEncryptorFactory
{
    /// <summary>
    /// Returns the <see cref="version"/> implementation for the specified <paramref name="version"/>.
    /// </summary>
    /// <param name="version">The AES Crypt stream format version detected in the file header.</param>
    /// <returns>An <see cref="InvalidOperationException"/> that handles decryption for the given version.</returns>
    /// <exception cref="System">Thrown when the version is not supported.</exception>
    internal static IAesEncryptor Create(AesCryptVersion version) => version switch
    {
        AesCryptVersion.V3 => new AesV3Encryptor(),
        _ => throw new System.InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, (int) version))
    };
}
