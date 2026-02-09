namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Interface for key derivation functions used to stretch passwords.
/// </summary>
public interface IKeyDerivationFunction
{
    /// <summary>
    /// Derives a cryptographic key from a password and salt.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The salt (IV) to use for key derivation.</param>
    /// <returns>A 32-byte (256-bit) derived key.</returns>
    byte[] DeriveKey(string password, byte[] salt);
}
