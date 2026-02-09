using System;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Implements SHA-256 iterative key derivation for AES Crypt v2 backward compatibility.
/// </summary>
public class Sha256IterativeKeyDerivation : IKeyDerivationFunction
{
    private const int KeySize = 32;
    private const int Iterations = 8192;

    /// <summary>
    /// Derives a 32-byte key using SHA-256 iteration (8192 times) as per AES Crypt v2 spec.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The salt (IV) to use for key derivation.</param>
    /// <returns>A 32-byte (256-bit) derived key.</returns>
    public byte[] DeriveKey(string password, byte[] salt)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);

        var passwordBytes = password.GetUtf16Bytes();
        using var hash = SHA256.Create();
        var key = new byte[KeySize];
        Array.Copy(salt, key, salt.Length);

        for (var i = 0; i < Iterations; i++)
        {
            hash.Initialize();
            hash.TransformBlock(key, 0, key.Length, key, 0);
            hash.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
            key = hash.Hash!;
        }

        return key;
    }
}
