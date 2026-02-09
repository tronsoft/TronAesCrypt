using System;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Implements PBKDF2-HMAC-SHA512 key derivation for AES Crypt v3.
/// </summary>
public class Pbkdf2HmacSha512KeyDerivation : IKeyDerivationFunction
{
    private readonly int _iterations;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pbkdf2HmacSha512KeyDerivation"/> class.
    /// </summary>
    /// <param name="iterations">The number of PBKDF2 iterations (default: 300,000).</param>
    public Pbkdf2HmacSha512KeyDerivation(int iterations = 300_000)
    {
        if (iterations <= 0)
        {
            throw new ArgumentException("Iterations must be greater than zero.", nameof(iterations));
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

        var passwordBytes = password.GetUtf16Bytes();

#pragma warning disable SYSLIB0060 // Rfc2898DeriveBytes obsolete warning
        using var pbkdf2 = new Rfc2898DeriveBytes(
            passwordBytes,
            salt,
            _iterations,
            HashAlgorithmName.SHA512
        );
#pragma warning restore SYSLIB0060

        return pbkdf2.GetBytes(32); // 256 bits
    }
}
