using System;
using System.Text;

namespace TRONSoft.TronAesCrypt.Core;

public static class BytesExtensions
{
    public static string GetUtf8String(this byte[] buffer)
    {
        if (buffer == null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        return Encoding.UTF8.GetString(buffer);
    }
}