using System;
using System.IO;

namespace TRONSoft.TronAesCrypt.Core.Extensions;

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

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes from the stream asynchronously.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when the stream ends before <paramref name="count"/> bytes are read (file is corrupt).</exception>
    internal static async System.Threading.Tasks.Task<byte[]> ReadBytesAsync(this Stream stream, int count, System.Threading.CancellationToken cancellationToken = default)
    {
        try
        {
            var buffer = new byte[count];
            await stream.ReadExactlyAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            return buffer;
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt, ex);
        }
    }
}
