using System;
using System.IO;
using System.Security.Cryptography;

namespace TRONSoft.TronAesCrypt.Core;

public class AesCrypt
{
    private const int AesBlockSize = 16;

    /// <summary>
    ///     The size of the key. For AES-256 that is 256/8 = 32
    /// </summary>
    private const int KeySize = 32;

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

        if (bufferSize % AesBlockSize != 0)
        {
            throw new ArgumentException("Buffer size must be a multiple of AES block size.");
        }

        if (password.Length > MaxPassLen)
        {
            throw new ArgumentException("The password is too long.");
        }

        if (!inStream.CanSeek)
        {
            throw new ArgumentException("Input stream must be seekable for decryption (v2/v3 format requires reading file header and trailer).", nameof(inStream));
        }

        var version = _aesCryptHeader.ReadHeader(inStream);

        int kdfIterations = 0;
        if (version == AesCryptVersion.V3)
        {
            var iterationBytes = inStream.ReadBytes(4);
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

        var ivMain = inStream.ReadBytes(16);

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

            var mainKeyAndIvRead = inStream.ReadBytes(48);

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

            var hmacMainKeyAndIvRead = inStream.ReadBytes(32);
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

        if (bufferSize % AesBlockSize != 0)
        {
            throw new ArgumentException("Buffer size must be a multiple of AES block size.");
        }

        if (password.Length > MaxPassLen)
        {
            throw new ArgumentException("The password is too long.");
        }

        if (kdfIterations < MinKdfIterations || kdfIterations > MaxKdfIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(kdfIterations), $"KDF iterations must be between {MinKdfIterations} and {MaxKdfIterations}");
        }

        var ivData = RandomSaltGenerator.Generate();
        var ivMainKey = RandomSaltGenerator.Generate();

        var kdf = new Pbkdf2HmacSha512KeyDerivation(kdfIterations);
        var key = kdf.DeriveKey(password, ivMainKey);

        var internalKey = RandomSaltGenerator.Generate(32);
        var encryptedMainKeyIv = EncryptMainKeyAndIv(key, ivMainKey, internalKey, ivData);

        _aesCryptHeader.WriteHeaderV3(outStream, kdfIterations);
        outStream.Write(ivMainKey, 0, ivMainKey.Length);
        outStream.Write(encryptedMainKeyIv, 0, encryptedMainKeyIv.Length);

        using (var hmacMainKeyIv = new HMACSHA256(key))
        {
            var dataToHash = new byte[encryptedMainKeyIv.Length + 1];
            Array.Copy(encryptedMainKeyIv, dataToHash, encryptedMainKeyIv.Length);
            dataToHash[encryptedMainKeyIv.Length] = 0x03;
            var hash = hmacMainKeyIv.ComputeHash(dataToHash);
            outStream.Write(hash, 0, hash.Length);
        }

        var hmac0Value = EncryptDataV3(inStream, outStream, internalKey, ivData, bufferSize);

        // V3: No modulo byte, just the HMAC
        outStream.Write(hmac0Value, 0, hmac0Value.Length);
    }



    private static byte[] EncryptDataV3(Stream inStream, Stream outStream, byte[] internalKey, byte[] iv, int bufferSize)
    {
        using var cipher = AesFactory.Create(internalKey, iv, usePkcs7Padding: true);
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
            AesDecryptorFactory.Create(version).Decrypt(inStream, outStream, internalKey, dataIv, bufferSize);
        }
        finally
        {
            if (internalKey != null) CryptographicOperations.ZeroMemory(internalKey);
            if (dataIv != null) CryptographicOperations.ZeroMemory(dataIv);
        }
    }

    private static byte[] EncryptMainKeyAndIv(byte[] key, byte[] iv, byte[] internalKey, byte[] ivInternal)
    {
        using var cipher = AesFactory.Create(key, iv);
        using var msEncrypt = new MemoryStream();
        using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(ivInternal, 0, ivInternal.Length);
        cryptoStream.Write(internalKey, 0, internalKey.Length);
        cryptoStream.FlushFinalBlock();

        return msEncrypt.ToArray();
    }

    private static (byte[], byte[]) DecryptMainKeyAndIv(byte[] key, byte[] iv, byte[] encryptedMainKeyIv)
    {
        using var cipher = AesFactory.Create(key, iv);
        using var msEncrypt = new MemoryStream(encryptedMainKeyIv);
        using var cryptoStream = new CryptoStream(msEncrypt, cipher.CreateDecryptor(), CryptoStreamMode.Read);
        var ivInternal = new byte[16];
        cryptoStream.ReadExactly(ivInternal, 0, ivInternal.Length);

        var internalKey = new byte[32];
        cryptoStream.ReadExactly(internalKey, 0, internalKey.Length);

        return (ivInternal, internalKey);
    }

}