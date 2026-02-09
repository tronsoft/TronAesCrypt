using System;
using System.IO;

namespace TRONSoft.TronAesCrypt.Core;

public class AesCryptHeader
{
    private const string AesHeader = "AES";
    public const string Version = "2.0.0";
    public const string AppName = "TronAesCrypt";

    public void WriteHeader(Stream stream)
    {
        WriteHeader(stream, AesCryptVersion.V3);
    }

    public void WriteHeader(Stream stream, AesCryptVersion version)
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

    public void WriteHeaderV3(Stream stream, int kdfIterations)
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

    public AesCryptVersion ReadHeader(Stream inStream)
    {
        var buffer = new byte[3];
        _ = inStream.Read(buffer, 0, buffer.Length);

        if (!buffer.GetUtf8String().Equals(AesHeader))
        {
            throw new InvalidOperationException(Resources.NotAnAescryptFile);
        }

        // Read version (AES Crypt file format)
        var versionByte = inStream.ReadByte();
        if (versionByte != 2 && versionByte != 3)
        {
            throw new InvalidOperationException($"Unsupported AES Crypt version: {versionByte}. Only versions 2 and 3 are supported.");
        }

        var version = (AesCryptVersion)versionByte;

        // Read reserved byte.
        inStream.ReadByte();

        // Read the extensions
        while (true)
        {
            buffer = new byte[2];
            var bytesRead = inStream.Read(buffer, 0, buffer.Length);
            if (bytesRead != 2)
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

            var amountOfBytesToRead = BitConverter.ToInt16(buffer, 0);
            buffer = new byte[amountOfBytesToRead];
            inStream.Read(buffer, 0, buffer.Length);
        }

        return version;
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
}