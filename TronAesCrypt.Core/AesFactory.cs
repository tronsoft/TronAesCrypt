using System;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

internal static class AesFactory
{
    private const int KeySize = 32;
    private const int AesBlockSize = 16;

    /// <summary>
    /// Creates and configures an AES-256-CBC cipher instance.
    /// </summary>
    /// <param name="key">The 32-byte encryption key.</param>
    /// <param name="iv">The 16-byte initialization vector.</param>
    /// <param name="usePkcs7Padding">
    ///     When <c>true</c>, uses PKCS#7 padding (AES Crypt v3).
    ///     When <c>false</c>, uses no padding (AES Crypt v2 — manual padding via modulo byte).
    /// </param>
    internal static Aes Create(byte[] key, byte[] iv, bool usePkcs7Padding = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key length must be {KeySize} bytes for AES-256.", nameof(key));
        }

        if (iv.Length != AesBlockSize)
        {
            throw new ArgumentException($"IV length must be {AesBlockSize} bytes.", nameof(iv));
        }

        var aes = Aes.Create();
        aes.KeySize = KeySize * 8;
        aes.BlockSize = AesBlockSize * 8;
        aes.Padding = usePkcs7Padding ? PaddingMode.PKCS7 : PaddingMode.None;
        aes.Mode = CipherMode.CBC;
        aes.Key = key;
        aes.IV = iv;
        return aes;
    }
}
