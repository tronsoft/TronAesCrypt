using System;

namespace TRONSoft.TronAesCrypt.Core.Encryptors;

/// <summary>
/// Creates the appropriate <see cref="IAesEncryptor"/> for a given AES Crypt stream format version.
/// </summary>
internal static class AesEncryptorFactory
{
    /// <summary>
    /// Returns an <see cref="IAesEncryptor"/> for the specified <paramref name="version"/>.
    /// </summary>
    /// <param name="version">The AES Crypt stream format version to encrypt with.</param>
    /// <returns>An <see cref="IAesEncryptor"/> that encrypts using the given version.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the version is not supported for encryption.</exception>
    internal static IAesEncryptor Create(AesCryptVersion version) => version switch
    {
        AesCryptVersion.V3 => new AesV3Encryptor(),
        _ => throw new System.InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, (int) version))
    };
}
