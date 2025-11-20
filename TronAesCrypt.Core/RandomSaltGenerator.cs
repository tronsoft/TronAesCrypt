using System;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

public static class RandomSaltGenerator
{
    /// <summary>
    ///     Creates a random salt that will be used to encrypt your file. This method is required on FileEncrypt.
    /// </summary>
    /// <returns>
    ///     Random bytes.
    /// </returns>
    public static byte[] Generate(int size = 16)
    {
        if (size < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be greater or equal to 1");
        }

        var data = new byte[size];
        using var rng = new RNGCryptoServiceProvider();
        rng.GetBytes(data);

        return data;
    }
}