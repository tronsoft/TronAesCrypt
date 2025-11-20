using System;
using System.Text;

namespace TRONSoft.TronAesCrypt.Core;

public static class BytesExtensions
{
    public static string GetUtf8String(this byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        return Encoding.UTF8.GetString(buffer);
    }
}