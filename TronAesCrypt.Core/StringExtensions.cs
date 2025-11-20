using System;
using System.Text;

namespace TRONSoft.TronAesCrypt.Core;

public static class StringExtensions
{
    public static byte[] GetUtf8Bytes(this string source)
    {
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return Encoding.UTF8.GetBytes(source);
    }
        
    public static byte[] GetUtf16Bytes(this string source)
    {
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }
            
        // little-endian UTF-16.
        return Encoding.Unicode.GetBytes(source);
    }
}