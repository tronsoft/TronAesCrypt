using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

public class AesCrypt
{
    // AES block size in bytes
    private const int AesBlockSize = 16;

    /// <summary>
    ///     The size of the key. For AES-256 that is 256/8 = 32
    /// </summary>
    private const int KeySize = 32;

    // maximum password length (number of chars)
    private const int MaxPassLen = 1024;

    // KDF iteration count limits to prevent CPU DoS attacks
    private const int MinKdfIterations = 10_000;
    private const int MaxKdfIterations = 10_000_000;

    private readonly AesCryptHeader _aesCryptHeader = new();

    /// <summary>
    /// A write-only stream that computes HMAC incrementally on all data written through it.
    /// </summary>
    private sealed class HmacComputingStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly HMAC _hmac;
        private bool _finalized;

        public HmacComputingStream(Stream innerStream, HMAC hmac)
        {
            _innerStream = innerStream;
            _hmac = hmac;
        }

        public byte[] GetHmacHash()
        {
            if (!_finalized)
            {
                _hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                _finalized = true;
            }
            return _hmac.Hash ?? Array.Empty<byte>();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _hmac.TransformBlock(buffer, offset, count, null, 0);
            _innerStream.Write(buffer, offset, count);
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position 
        { 
            get => throw new NotSupportedException(); 
            set => throw new NotSupportedException(); 
        }
        public override void Flush() => _innerStream.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>
    /// A read-only stream that limits the number of bytes that can be read from the inner stream.
    /// </summary>
    private sealed class LimitedReadStream : Stream
    {
        private readonly Stream _innerStream;
        private long _remaining;

        public LimitedReadStream(Stream innerStream, long maxBytes)
        {
            _innerStream = innerStream;
            _remaining = maxBytes;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0)
            {
                return 0;
            }

            var bytesToRead = (int)Math.Min(count, _remaining);
            var bytesRead = _innerStream.Read(buffer, offset, bytesToRead);
            _remaining -= bytesRead;
            return bytesRead;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    public void EncryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024, int kdfIterations = 300_000)
    {
        using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write);
        EncryptStream(inputStream, outputStream, password, bufferSize, kdfIterations);
    }

    public void DecryptFile(string inputFileName, string outputFileName, string password, int bufferSize = 64 * 1024)
    {
        using var inputStream = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFileName, FileMode.Create, FileAccess.Write);
        DecryptStream(inputStream, outputStream, password, bufferSize);
    }

    /// <summary>
    /// Decrypt the stream. Automatically detects and supports both v2 and v3 stream formats.
    /// </summary>
    /// <param name="inStream">The input stream.</param>
    /// <param name="outStream">The output stream for decrypted data</param>
    /// <param name="password">The password to use for decrypting.</param>
    /// <param name="bufferSize">
    ///     bufferSize: decryption buffer size, must be a multiple of
    ///     AES block size (16)
    ///     using a larger buffer speeds up things when dealing
    ///     with big files
    /// </param>
    /// <remarks>
    /// The input stream must be seekable because the AES Crypt format requires:
    /// 1. Reading the file header first to determine the version (v2 or v3) and iteration count
    /// 2. Seeking to the trailer at the end of the file to verify the HMAC after decryption
    /// Non-seekable streams (e.g., network streams, pipes) are not supported for decryption.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    ///     Thrown when the file is corrupt, the password is incorrect, or the stream format is unsupported.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     Thrown when the input stream is not seekable.
    /// </exception>
    public void DecryptStream(Stream inStream, Stream outStream, string password, int bufferSize)
    {
        ArgumentNullException.ThrowIfNull(inStream);
        ArgumentNullException.ThrowIfNull(outStream);
        ArgumentNullException.ThrowIfNull(password);

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

        // Validate stream seekability
        if (!inStream.CanSeek)
        {
            throw new ArgumentException("Input stream must be seekable for decryption (v2/v3 format requires reading file header and trailer).", nameof(inStream));
        }

        // Read header and detect version
        var version = _aesCryptHeader.ReadHeader(inStream);

        // Read KDF iteration count for v3
        int kdfIterations = 0;
        if (version == AesCryptVersion.V3)
        {
            var iterationBytes = ReadBytes(inStream, 4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(iterationBytes);
            }
            kdfIterations = BitConverter.ToInt32(iterationBytes, 0);
            
            // Add validation (also handles negative/zero check from Issue #2)
            if (kdfIterations < MinKdfIterations || kdfIterations > MaxKdfIterations)
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }
        }

        // read the iv used to encrypt the main iv and the encryption key
        var ivMain = ReadBytes(inStream, 16);

        // Derive key based on version
        byte[] key = null;
        try
        {
            if (version == AesCryptVersion.V2)
            {
                var kdf = new Sha256IterativeKeyDerivation();
                key = kdf.DeriveKey(password, ivMain);
            }
            else // V3
            {
                var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
                key = kdf.DeriveKey(password, ivMain);
            }

            // read encrypted main iv and key
            var mainKeyAndIvRead = ReadBytes(inStream, 48);

            using var hmac1 = new HMACSHA256(key);
            byte[] hmacMainIvAndKeyActual;

            if (version == AesCryptVersion.V2)
            {
                // V2: HMAC without version byte
                hmacMainIvAndKeyActual = hmac1.ComputeHash(mainKeyAndIvRead);
            }
            else // V3
            {
                // V3: HMAC with version byte appended
                var dataToHash = new byte[mainKeyAndIvRead.Length + 1];
                Array.Copy(mainKeyAndIvRead, dataToHash, mainKeyAndIvRead.Length);
                dataToHash[mainKeyAndIvRead.Length] = 0x03;
                hmacMainIvAndKeyActual = hmac1.ComputeHash(dataToHash);
            }

            // read HMAC-SHA256 of the encrypted iv and key
            var hmacMainKeyAndIvRead = ReadBytes(inStream, 32);
            if (!CryptographicOperations.FixedTimeEquals(hmacMainKeyAndIvRead, hmacMainIvAndKeyActual))
            {
                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
            }

            DecryptData(inStream, outStream, key, ivMain, mainKeyAndIvRead, bufferSize, version);
        }
        finally
        {
            if (key != null)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    /// <summary>
    /// Encrypt the stream using AES Crypt v3 format with PBKDF2-HMAC-SHA512 key derivation.
    /// </summary>
    /// <param name="inStream">The input stream.</param>
    /// <param name="outStream">The aes crypt output stream</param>
    /// <param name="password">The password to use for encrypting.</param>
    /// <param name="bufferSize">
    ///     bufferSize: encryption buffer size, must be a multiple of
    ///     AES block size (16)
    ///     using a larger buffer speeds up things when dealing
    ///     with big files
    /// </param>
    /// <param name="kdfIterations">
    ///     The number of PBKDF2-HMAC-SHA512 iterations for key derivation (default: 300,000).
    ///     Higher values provide better security against brute-force attacks but increase processing time.
    /// </param>
    /// <returns>The encrypted stream.</returns>
    public void EncryptStream(Stream inStream, Stream outStream, string password, int bufferSize, int kdfIterations = 300_000)
    {
        ArgumentNullException.ThrowIfNull(inStream);
        ArgumentNullException.ThrowIfNull(outStream);
        ArgumentNullException.ThrowIfNull(password);

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

        // Validate KDF iterations bounds
        if (kdfIterations < MinKdfIterations || kdfIterations > MaxKdfIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(kdfIterations), $"KDF iterations must be between {MinKdfIterations} and {MaxKdfIterations}");
        }

        var ivData = RandomSaltGenerator.Generate();
        var ivMainKey = RandomSaltGenerator.Generate();

        // Use PBKDF2-HMAC-SHA512 for v3
        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        var key = kdf.DeriveKey(password, ivMainKey);

        // create hmac for cipher text
        var internalKey = RandomSaltGenerator.Generate(32);

        // encrypt the main key and iv
        var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);

        // Write v3 header with KDF iteration count
        _aesCryptHeader.WriteHeaderV3(outStream, kdfIterations);

        // write the iv used to encrypt the main iv and the encryption key
        outStream.Write(ivMainKey, 0, ivMainKey.Length);

        // write encrypted main iv and key
        outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);

        // write HMAC-SHA256 of the encrypted iv and key (with version byte 0x03 appended)
        using (var hmacMainKeyIv = new HMACSHA256(key))
        {
            var dataToHash = new byte[encryptedMainKeyIv.Length + 1];
            Array.Copy(encryptedMainKeyIv, dataToHash, encryptedMainKeyIv.Length);
            dataToHash[encryptedMainKeyIv.Length] = 0x03; // Append version byte
            var hash = hmacMainKeyIv.ComputeHash(dataToHash);
            outStream.Write(hash, 0, hash.Length);
        }

        // Encrypt the 'real' data using PKCS#7 padding
        var hmac0Value = EncryptDataV3(inStream, outStream, internalKey, ivData, bufferSize);

        // V3: No modulo byte, just the HMAC
        outStream.Write(hmac0Value, 0, hmac0Value.Length);
    }



    private static byte[] EncryptDataV3(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
    {
        using var cipher = CreateAes(internalKey, iv, usePkcs7Padding: true);
        using var hmac0 = new HMACSHA256(internalKey);
        hmac0.Initialize();
        
        using var hmacStream = new HmacComputingStream(outStream, hmac0);
        using var cryptoStream = new CryptoStream(hmacStream, cipher.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true);
        int bytesRead;
        var buffer = new byte[bufferSize];
        while ((bytesRead = inStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, bytesRead);
        }

        cryptoStream.FlushFinalBlock();

        return hmacStream.GetHmacHash();
    }

    private static void DecryptData(Stream inStream, Stream outStream, byte[] key, byte[] ivMain, byte[] mainKeyAndIv, int bufferSize, AesCryptVersion version)
    {
        var (dataIv, internalKey) = DecryptMainKeyAndIv(key, ivMain, mainKeyAndIv);
        try
        {
            var currentPosition = inStream.Position;

            if (version == AesCryptVersion.V2)
            {
                // V2: Has modulo byte before final HMAC
                var endPositionEncryptedData = inStream.Length - 32 - 1;

                // Get padding and hmac
                inStream.Position = endPositionEncryptedData;
                var padding = (16 - ReadBytes(inStream, 1)[0]) % 16;
                var hmacEncryptedData = ReadBytes(inStream, 32);

                // Reset the position to the beginning of the encrypted data
                inStream.Position = currentPosition;

                // Get hmac
                using var hmac0 = new HMACSHA256(internalKey);
                hmac0.Initialize();

                // Get the cipher
                using var cipher = CreateAes(internalKey, dataIv, usePkcs7Padding: false);
                using var decrypter = cipher.CreateDecryptor();
                
                // First read as much data as possible.
                ReadEncryptedBytes(bufferSize);

                // read the remaining
                ReadEncryptedBytes();

                // Everything read but the last block need to remove padding
                if (inStream.Position != endPositionEncryptedData)
                {
                    var lastBlock = ReadBytes(inStream, AesBlockSize);
                    hmac0.TransformBlock(lastBlock, 0, lastBlock.Length, null, 0);

                    decrypter.TransformBlock(lastBlock, 0, lastBlock.Length, lastBlock, 0);
                    outStream.Write(lastBlock, 0, lastBlock.Length - padding);
                }

                decrypter.TransformFinalBlock([], 0, 0);
                hmac0.TransformFinalBlock([], 0, 0);
                if (!CryptographicOperations.FixedTimeEquals(hmac0.Hash!, hmacEncryptedData))
                {
                    throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                }
                
                
                void ReadEncryptedBytes(int bytesToRead = AesBlockSize)
                {
                    var buffer = new byte[bytesToRead];
                    while (inStream.Position < endPositionEncryptedData - bytesToRead)
                    {
                        // Loop to ensure we read the full amount requested
                        var totalBytesRead = 0;
                        while (totalBytesRead < bytesToRead)
                        {
                            var bytesReadInIteration = inStream.Read(buffer, totalBytesRead, bytesToRead - totalBytesRead);
                            if (bytesReadInIteration == 0)
                            {
                                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                            }
                            totalBytesRead += bytesReadInIteration;
                        }
                        
                        // Use totalBytesRead for all operations
                        hmac0.TransformBlock(buffer, 0, totalBytesRead, null, 0);
                        decrypter.TransformBlock(buffer, 0, totalBytesRead, buffer, 0);
                        outStream.Write(buffer, 0, totalBytesRead);
                    }
                }
            }
            else // V3
            {
                // V3: No modulo byte, just HMAC at the end, and uses PKCS#7 padding
                var endPositionEncryptedData = inStream.Length - 32;
                var encryptedLength = endPositionEncryptedData - currentPosition;

                // Get hmac
                inStream.Position = endPositionEncryptedData;
                var hmacEncryptedData = ReadBytes(inStream, 32);

                // Pass 1: Verify HMAC by reading through ciphertext incrementally
                inStream.Position = currentPosition;
                using (var hmac0 = new HMACSHA256(internalKey))
                {
                    hmac0.Initialize();
                    var buffer = new byte[bufferSize];
                    var remaining = encryptedLength;
                    
                    while (remaining > 0)
                    {
                        var bytesToRead = (int)Math.Min(remaining, buffer.Length);
                        var totalBytesRead = 0;
                        
                        // Ensure we read the full amount requested
                        while (totalBytesRead < bytesToRead)
                        {
                            var bytesRead = inStream.Read(buffer, totalBytesRead, bytesToRead - totalBytesRead);
                            if (bytesRead == 0)
                            {
                                throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                            }
                            totalBytesRead += bytesRead;
                        }
                        
                        hmac0.TransformBlock(buffer, 0, totalBytesRead, null, 0);
                        remaining -= totalBytesRead;
                    }
                    
                    hmac0.TransformFinalBlock([], 0, 0);
                    if (!CryptographicOperations.FixedTimeEquals(hmac0.Hash!, hmacEncryptedData))
                    {
                        throw new InvalidOperationException(Resources.TheFileIsCorrupt);
                    }
                }

                // Pass 2: Seek back and decrypt with PKCS#7 padding handling
                inStream.Position = currentPosition;
                using var limitedStream = new LimitedReadStream(inStream, encryptedLength);
                using var cipher = CreateAes(internalKey, dataIv, usePkcs7Padding: true);
                using var cryptoStream = new CryptoStream(limitedStream, cipher.CreateDecryptor(), CryptoStreamMode.Read);
                
                var decryptBuffer = new byte[bufferSize];
                int bytesReadFromDecrypt;

                while ((bytesReadFromDecrypt = cryptoStream.Read(decryptBuffer, 0, decryptBuffer.Length)) > 0)
                {
                    outStream.Write(decryptBuffer, 0, bytesReadFromDecrypt);
                }
            }
        }
        finally
        {
            if (internalKey != null)
            {
                CryptographicOperations.ZeroMemory(internalKey);
            }
            if (dataIv != null)
            {
                CryptographicOperations.ZeroMemory(dataIv);
            }
        }
    }

    private static Aes CreateAes(byte[] key, byte[] iv, bool usePkcs7Padding = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        if (key.Length != KeySize)
        {
            throw new ArgumentException($@"Key length must be {KeySize} bytes for AES-256.", nameof(key));
        }
        if (iv.Length != AesBlockSize)
        {
            throw new ArgumentException($@"IV length must be {AesBlockSize} bytes.", nameof(iv));
        }

        var aes = Aes.Create();
        aes.KeySize = KeySize * 8;
        aes.BlockSize = AesBlockSize * 8;
        aes.Padding = usePkcs7Padding ? PaddingMode.PKCS7 : PaddingMode.None;
        aes.Mode = CipherMode.CBC;
        aes.Key = key;
        aes.IV = iv;
        return aes;
    }

    private static byte[] EncryptMainKeyAndIv(byte[] key, byte[] iv, byte[] internalKey, byte[] ivInternal)
    {
        using var cipher = CreateAes(key, iv);
        using var msEncrypt = new MemoryStream();
        using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(ivInternal, 0, ivInternal.Length);
        cryptoStream.Write(internalKey, 0, internalKey.Length);
        cryptoStream.FlushFinalBlock();

        return msEncrypt.ToArray();
    }

    private static (byte[], byte[]) DecryptMainKeyAndIv(byte[] key, byte[] iv, byte[] encryptedMainKeyIv)
    {
        using var cipher = CreateAes(key, iv);
        using var msEncrypt = new MemoryStream(encryptedMainKeyIv);
        using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateDecryptor(), CryptoStreamMode.Read);
        var ivInternal = new byte[16];
        cryptoStream.ReadExactly(ivInternal, 0, ivInternal.Length);

        var internalKey = new byte[32];
        cryptoStream.ReadExactly(internalKey, 0, internalKey.Length);

        return (ivInternal, internalKey);
    }



    private static byte[] ReadBytes(Stream stream, int bufferSize)
    {
        try
        {
            var buffer = new byte[bufferSize];
            stream.ReadExactly(buffer, 0, bufferSize);
            return buffer;
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidOperationException(Resources.TheFileIsCorrupt, ex);
        }
    }
}