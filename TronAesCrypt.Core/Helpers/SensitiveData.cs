using System;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core.Helpers;

/// <summary>
/// A disposable wrapper for sensitive byte arrays that ensures the memory is zeroed out when disposed.
/// </summary>
internal sealed class SensitiveData : IDisposable
{
    private readonly byte[] _data;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SensitiveData"/> class.
    /// </summary>
    /// <param name="data">The sensitive byte array to wrap.</param>
    public SensitiveData(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    /// <summary>
    /// Gets a span over the sensitive data.
    /// </summary>
    public Span<byte> Span => _data.AsSpan();

    /// <summary>
    /// Gets the underlying byte array.
    /// </summary>
    public byte[] Data => _data;

    /// <summary>
    /// Implicitly converts a <see cref="SensitiveData"/> instance to its underlying byte array.
    /// </summary>
    /// <param name="data">The <see cref="SensitiveData"/> instance.</param>
    public static implicit operator byte[](SensitiveData data) => data.Data;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_data);
        _disposed = true;
    }
}
