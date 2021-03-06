using System;

namespace TronAesCrypt.Main.Tests
{
    /// <summary>
    /// Class to do some basic operations on AesCrypt.
    /// </summary>
    public static class AesCryptProcessRunner
    {
        public static bool CanEncrypt(string fileName, string outputFileName, string password) => CanCrypt(fileName, outputFileName, password);

        public static bool CanDecrypt(string fileName, string outputFileName, string password) => CanCrypt(fileName, outputFileName, password, false);

        private static bool CanCrypt(string fileName, string outputFileName, string password, bool encrypt = true)
        {
            if (string.IsNullOrWhiteSpace(fileName))
            {
                throw new ArgumentNullException(nameof(fileName));
            }

            if (string.IsNullOrWhiteSpace(outputFileName))
            {
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(outputFileName));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var methodInfo = typeof(Program).Assembly.EntryPoint;
            if (methodInfo == null)
            {
                return false;
            }

            var cryptMethod = encrypt ? "-e" : "-d";
            var args = new[] {cryptMethod, "-p", password, "-o", outputFileName, "-f", fileName};
            methodInfo.Invoke(null, new object[] {args});
            var exitCode = Convert.ToInt32(0);
            return exitCode == 0;
        }
    }
}