using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core.Tests
{
    internal static class StringExtensions
    {
        public static string AsSha256OfFile(this string fileName)
        {
            if (fileName == null)
            {
                throw new ArgumentNullException(nameof(fileName));
            }

            var bytes = File.ReadAllBytes(fileName);
            bytes = SHA256.Create().ComputeHash(bytes);
            return string.Concat(bytes.Select(b => $"{b:x2}"));
        }
    }
}