using System;
using System.IO;

namespace TRONSoft.TronAesCrypt.Core
{
    public class AesCryptHeader
    {
        private const string AesHeader = "AES";
        public const string Version = "0.1.0";
        public const string AppName = "TronAesCrypt";

        public void WriteHeader(Stream stream)
        {
            // Write header.
            var buffer = AesHeader.GetUtf8Bytes();
            stream.Write(buffer, 0, buffer.Length);

            // write version (AES Crypt version 2 file format -
            // see https://www.aescrypt.com/aes_file_format.html)
            stream.WriteByte(2);

            // reserved byte (set to zero)
            stream.WriteByte(0);

            WriteExtensions(stream);
        }

        public void ReadHeader(Stream inStream)
        {
            var buffer = new byte[3];
            inStream.Read(buffer, 0, buffer.Length);

            if (!buffer.GetUtf8String().Equals(AesHeader))
            {
                throw new InvalidOperationException(Resources.NotAnAescryptFile);
            }

            // write version (AES Crypt version 2 file format -
            // see https://www.aescrypt.com/aes_file_format.html)
            var version = inStream.ReadByte();
            if (version != 2)
            {
                throw new InvalidOperationException(Resources.OnlyAesCryptVersion2IsSupported);
            }

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
}