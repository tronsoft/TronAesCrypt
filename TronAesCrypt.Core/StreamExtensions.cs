using System;
using System.IO;

namespace TRONSoft.TronAesCrypt.Core;

internal static class StreamExtensions
{
    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes from the stream.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when the stream ends before <paramref name="count"/> bytes are read (file is corrupt).</exception>
    internal static byte[] ReadBytes(this Stream stream, int count)
    {
        try
        {
            var buffer = new byte[count];
            stream.ReadExactly(buffer, 0, count);
            return buffer;
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt, ex);
        }
    }
}
