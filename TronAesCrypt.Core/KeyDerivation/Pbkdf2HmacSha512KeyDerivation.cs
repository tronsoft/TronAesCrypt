using System;
using System.Security.Cryptography;
using TRONSoft.TronAesCrypt.Core.Extensions;

namespace TRONSoft.TronAesCrypt.Core.KeyDerivation;

/// <summary>
/// Implements PBKDF2-HMAC-SHA512 key derivation for AES Crypt v3.
/// </summary>
internal class Pbkdf2HmacSha512KeyDerivation : IKeyDerivationFunction
{
    private const int MinKdfIterations = 10_000;
    private const int MaxKdfIterations = 10_000_000;

    private readonly int _iterations;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pbkdf2HmacSha512KeyDerivation"/> class.
    /// </summary>
    /// <param name="iterations">The number of PBKDF2 iterations (default: 300,000).</param>
    public Pbkdf2HmacSha512KeyDerivation(int iterations = 300_000)
    {
        if (iterations < MinKdfIterations || iterations > MaxKdfIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), @$"Iterations must be between {MinKdfIterations:N0} and {MaxKdfIterations:N0}");
        }

        _iterations = iterations;
    }

    /// <summary>
    /// Derives a 32-byte key using PBKDF2-HMAC-SHA512.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The salt (IV) to use for key derivation.</param>
    /// <returns>A 32-byte (256-bit) derived key.</returns>
    public byte[] DeriveKey(string password, byte[] salt)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);

        // AES Crypt stream format v3 uses raw UTF-8 bytes for the PBKDF2 password input.
        // This differs from v2, which used UTF-16 LE. Using UTF-8 here is required for
        // interoperability with the official AES Crypt 4.x implementation.
        var passwordBytes = password.GetUtf8Bytes();
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                _iterations,
                HashAlgorithmName.SHA512,
                32); // 256 bits
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}
