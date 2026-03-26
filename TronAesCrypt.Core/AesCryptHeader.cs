using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TRONSoft.TronAesCrypt.Core.Extensions;

namespace TRONSoft.TronAesCrypt.Core;

public class AesCryptHeader
{
    private const string AesHeader = "AES";
    public const string Version = "2.0.0";
    public const string AppName = "TronAesCrypt";

    [Obsolete("Writing v2 headers is no longer supported. Use WriteHeader(Stream, int) to write a v3 header instead.", error: true)]
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    public void WriteHeader(Stream stream)
    {
        throw new NotSupportedException("Writing AES Crypt v2 headers is no longer supported in this version.");
    }

    private void WriteHeader(Stream stream, AesCryptVersion version)
    {
        // Write header.
        var buffer = AesHeader.GetUtf8Bytes();
        stream.Write(buffer, 0, buffer.Length);

        // Write version byte
        stream.WriteByte((byte)version);

        // reserved byte (set to zero)
        stream.WriteByte(0);

        WriteExtensions(stream);
    }

    public void WriteHeader(Stream stream, int kdfIterations)
    {
        WriteHeader(stream, AesCryptVersion.V3);

        // Write KDF iteration count (4 bytes, network byte order / big-endian)
        var iterationBytes = BitConverter.GetBytes(kdfIterations);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        stream.Write(iterationBytes, 0, iterationBytes.Length);
    }

    public AesCryptVersion PeekAesCryptVersion(Stream inStream)
    {
        var originalPosition = inStream.Position;
        try
        {
            ReadAesMarker(inStream);
            var versionByte = inStream.ReadByte();
            if (versionByte != 2 && versionByte != 3)
            {
                throw new InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, versionByte));
            }
            return (AesCryptVersion)versionByte;
        }
        finally
        {
            inStream.Seek(originalPosition, SeekOrigin.Begin);
        }
    }

    public async Task<AesCryptVersion> PeekAesCryptVersionAsync(Stream inStream, CancellationToken cancellationToken = default)
    {
        var originalPosition = inStream.Position;
        try
        {
            await ReadAesMarkerAsync(inStream, cancellationToken).ConfigureAwait(false);
            var buffer = new byte[1];
            await inStream.ReadExactlyAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            var versionByte = buffer[0];
            if (versionByte != 2 && versionByte != 3)
            {
                throw new InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, versionByte));
            }
            return (AesCryptVersion)versionByte;
        }
        finally
        {
            inStream.Seek(originalPosition, SeekOrigin.Begin);
        }
    }

    public AesCryptVersion ReadHeader(Stream inStream)
    {
        ReadAesMarker(inStream);

        // Read version (AES Crypt file format)
        var versionByte = inStream.ReadByte();
        if (versionByte != 2 && versionByte != 3)
        {
            throw new InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, versionByte));
        }

        var version = (AesCryptVersion)versionByte;

        // Read reserved byte.
        inStream.ReadByte();

        ReadExtensions(inStream);

        return version;
    }

    public async Task<AesCryptVersion> ReadHeaderAsync(Stream inStream, CancellationToken cancellationToken = default)
    {
        await ReadAesMarkerAsync(inStream, cancellationToken).ConfigureAwait(false);

        // Read version (AES Crypt file format)
        var buffer = new byte[1];
        await inStream.ReadExactlyAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        var versionByte = buffer[0];
        if (versionByte != 2 && versionByte != 3)
        {
            throw new InvalidOperationException(string.Format(Resources.UnsupportedAesCryptVersion, versionByte));
        }

        var version = (AesCryptVersion)versionByte;

        // Read reserved byte.
        await inStream.ReadExactlyAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);

        await ReadExtensionsAsync(inStream, cancellationToken).ConfigureAwait(false);

        return version;
    }

    private static void ReadExtensions(Stream inStream)
    {
        // Read the extensions
        while (true)
        {
            var buffer = new byte[2];
            var extensionLengthBytesRead = inStream.Read(buffer, 0, buffer.Length);
            if (extensionLengthBytesRead != 2)
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

            if (buffer[0] == 0 && buffer[1] == 0)
            {
                break;
            }

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            var amountOfBytesToRead = BitConverter.ToUInt16(buffer, 0);
            
            // Add validation for extension length
            if (amountOfBytesToRead == 0)
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }
            
            buffer = new byte[amountOfBytesToRead];
            
            // Replace single Read with loop to handle short reads
            var totalBytesRead = 0;
            while (totalBytesRead < buffer.Length)
            {
                var bytesReadThisIteration = inStream.Read(buffer, totalBytesRead, buffer.Length - totalBytesRead);
                if (bytesReadThisIteration <= 0)
                {
                    throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                }
                totalBytesRead += bytesReadThisIteration;
            }
        }
    }

    private static async Task ReadExtensionsAsync(Stream inStream, CancellationToken cancellationToken)
    {
        // Read the extensions
        while (true)
        {
            var buffer = new byte[2];
            try
            {
                await inStream.ReadExactlyAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            }
            catch (EndOfStreamException ex)
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt, ex);
            }

            if (buffer[0] == 0 && buffer[1] == 0)
            {
                break;
            }

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            var amountOfBytesToRead = BitConverter.ToUInt16(buffer, 0);
            
            // Add validation for extension length
            if (amountOfBytesToRead == 0)
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }
            
            buffer = new byte[amountOfBytesToRead];
            
            // Replace single Read with loop to handle short reads
            var totalBytesRead = 0;
            while (totalBytesRead < buffer.Length)
            {
                var bytesReadThisIteration = await inStream.ReadAsync(buffer.AsMemory(totalBytesRead, buffer.Length - totalBytesRead), cancellationToken).ConfigureAwait(false);
                if (bytesReadThisIteration <= 0)
                {
                    throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                }
                totalBytesRead += bytesReadThisIteration;
            }
        }
    }

    private void WriteExtensions(Stream outStream)
    {
        // Created-by extensions
        var createdBy = "CREATED_BY";
        var appName = $"{AppName} {Version}";

        // Write CREATED_BY extension length
        outStream.WriteByte(0);
        outStream.WriteByte((byte) ((createdBy + appName).Length + 1));

        // Write the CREATED_BY extension
        var buffer = createdBy.GetUtf8Bytes();
        outStream.Write(buffer, 0, buffer.Length);
        outStream.WriteByte(0);

        buffer = appName.GetUtf8Bytes();
        outStream.Write(buffer, 0, buffer.Length);

        // Write extensions container
        outStream.WriteByte(0);
        outStream.WriteByte(128);

        buffer = new byte[128];
        outStream.Write(buffer, 0, buffer.Length);

        // write end-of-extensions tag
        outStream.WriteByte(0);
        outStream.WriteByte(0);
    }

    private static void ReadAesMarker(Stream inStream)
    {
        var buffer = new byte[3];
        try
        {
            inStream.ReadExactly(buffer, 0, 3);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt, ex);
        }
        if (!buffer.GetUtf8String().Equals(AesHeader))
        {
            throw new InvalidOperationException(Resources.NotAnAescryptFile);
        }
    }

    private static async Task ReadAesMarkerAsync(Stream inStream, CancellationToken cancellationToken)
    {
        var buffer = new byte[3];
        try
        {
            await inStream.ReadExactlyAsync(buffer.AsMemory(0, 3), cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt, ex);
        }
        if (!buffer.GetUtf8String().Equals(AesHeader))
        {
            throw new InvalidOperationException(Resources.NotAnAescryptFile);
        }
    }
}
