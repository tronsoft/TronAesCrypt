using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace TRONSoft.TronAesCrypt.Core
{
    public class AesCrypt
    {
        //AES block size in bytes
        public const int AesBlockSize = 16;
        
        // encryption/decryption buffer size - 64K
        public const int BufferSize = 64 * 1024;
        
        // maximum password length (number of chars)
        public const int MaxPassLen = 1024;
         
        private static readonly byte[] AesHeader = "AES".GetUtf8Bytes();

        /// <summary>
        ///     Creates a random salt that will be used to encrypt your file. This method is required on FileEncrypt.
        /// </summary>
        /// <returns></returns>
        private static byte[] GenerateRandomSalt(int size = AesBlockSize)
        {
            if (size < 1)
            {
                throw new ArgumentException("Size must be greater or equal to 1");
            }
            
            var data = new byte[size];
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(data);

            return data;
        }

        public void Encrypt(string fileName, string password, Stream stream)
        {
            // http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            var salt = GenerateRandomSalt(AesBlockSize);
            var aes = CreateAes(password, salt);
            using var file2Encrypt = new FileStream(fileName, FileMode.OpenOrCreate);
            using var cryptoStream = new CryptoStream(
                file2Encrypt,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write);

            // write salt to the beginning of the output file, so in this case can be random every time
            file2Encrypt.Write(salt, 0, salt.Length);

            int read;
            var buffer = new byte[1024 * 1024];
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cryptoStream.Write(buffer, 0, read);
            }

            // Close all the connections.
            cryptoStream.Close();
            file2Encrypt.Close();
        }

        public FileStream Decrypt(string encryptedFileName, string decryptedFileName, string password)
        {
            using var encryptedFile = new FileStream(encryptedFileName, FileMode.Open);

            // read the salt
            var salt = new byte[32];
            encryptedFile.Read(salt, 0, salt.Length);

            using var aes = CreateAes(password, salt);
            using var cryptoStream = new CryptoStream(encryptedFile, aes.CreateDecryptor(), CryptoStreamMode.Read);
            var decryptedFile = new FileStream(decryptedFileName, FileMode.Create);

            int read;
            var buffer = new byte[1024 * 1024];
            while ((read = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                decryptedFile.Write(buffer, 0, read);
            }

            cryptoStream.Close();

            return decryptedFile;
        }

        private static RijndaelManaged CreateAes(string password, byte[] salt)
        {
            const int keySize = 256;
            const int blockSize = 128;

            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            return new RijndaelManaged
            {
                KeySize = keySize,
                BlockSize = blockSize,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                // http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
                // "What it does is repeatedly hash the user password along with the salt." High iteration counts.
                Key = key.GetBytes(keySize / 8),
                IV = key.GetBytes(128 / 8)
            };
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inStream">The input stream.</param>
        /// <param name="outStream">The aescrypt output stream</param>
        /// <param name="password">The password to use for encrypting.</param>
        /// <param name="bufferSize">
        /// bufferSize: encryption buffer size, must be a multiple of
        /// AES block size (16)
        /// using a larger buffer speeds up things when dealing
        /// with big files
        /// </param>
        /// <returns>The encrypted stream.</returns>
        public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
        {
            // Validate the buffer size 
            if (bufferSize % AesBlockSize != 0)
            {
                throw new ArgumentException("Buffer size must be a multiple of AES block size.");
            }
            
            // Validate password  length
            if (password.Length > MaxPassLen)
            {
                throw new ArgumentException("The password is too long.");
            }
            
            
            
            // http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            var iv0 = GenerateRandomSalt();
            /*var aes = CreateAes(password, iv0);
            using var encryptedStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(
                encryptedStream,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write);

            // write salt to the beginning of the output file, so in this case can be random every time
            outStream.Write(salt, 0, salt.Length);

            int read;
            var buffer = new byte[1024 * 1024];
            while ((read = inStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cryptoStream.Write(buffer, 0, read);
            }

            // Close all the connections.
            cryptoStream.Close();
            encryptedStream.Close();*/
            
            WriteHeader(outStream);
            outStream.Position = 0;
        }

        private static void WriteHeader(Stream outStream)
        {
            // Write header.
            outStream.Write(AesHeader);

            // write version (AES Crypt version 2 file format -
            // see https://www.aescrypt.com/aes_file_format.html)
            outStream.WriteByte(2);

            // reserved byte (set to zero)
            outStream.WriteByte(0);

            WriteExtensions(outStream);
        }

        private static void WriteExtensions(Stream outStream)
        {
            // Created-by extensions
            var createdBy = "CREATED_BY";
            var appName = "TronAesCrypt";

            // Write CREATED_BY extension length
            outStream.WriteByte(0);
            outStream.WriteByte((byte) ((createdBy + appName).Length + 1));

            // Write the CREATED_BY extension
            outStream.Write(createdBy.GetUtf8Bytes());
            outStream.WriteByte(0);
            outStream.Write(appName.GetUtf8Bytes());

            // Write extensions container
            outStream.WriteByte(0);
            outStream.WriteByte(80);

            outStream.Write(new byte[128]);

            // write end-of-extensions tag
            outStream.WriteByte(0);
            outStream.WriteByte(0);
        }

        // private string StretchPasswordAndIv(string password, byte[] iv)
        // {
        //     var digest = iv + 
        // }
    }
}