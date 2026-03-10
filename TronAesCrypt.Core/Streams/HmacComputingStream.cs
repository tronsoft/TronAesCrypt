using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core.Streams;

/// <summary>
///     A write-only stream that computes HMAC incrementally on all data written through it.
/// </summary>
internal sealed class HmacComputingStream(Stream innerStream, HMAC hmac) : Stream
{
    private bool _finalized;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public byte[] GetHmacHash()
    {
        if (!_finalized)
        {
            hmac.TransformFinalBlock([], 0, 0);
            _finalized = true;
        }

        if (hmac.Hash is null)
        {
            throw new InvalidOperationException("HMAC hash is not available after finalization.");
        }

        return hmac.Hash;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        hmac.TransformBlock(buffer, offset, count, null, 0);
        innerStream.Write(buffer, offset, count);
    }

    public override void Flush() => innerStream.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}