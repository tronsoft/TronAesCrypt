namespace TRONSoft.TronAesCrypt.Core;

/// <summary>
/// Represents the AES Crypt file format version.
/// </summary>
public enum AesCryptVersion : byte
{
    /// <summary>
    /// AES Crypt file format version 2.
    /// Uses SHA-256 iteration (8192 times) for key derivation.
    /// </summary>
    V2 = 2,

    /// <summary>
    /// AES Crypt file format version 3.
    /// Uses PBKDF2-HMAC-SHA512 for key derivation with configurable iterations.
    /// </summary>
    V3 = 3
}
