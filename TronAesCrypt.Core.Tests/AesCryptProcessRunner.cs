using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace TRONSoft.TronAesCrypt.Main
{
    /// <summary>
    /// Class to do some basic operations on AesCrypt.
    /// </summary>
    public static class AesCryptProcessRunner
    {
        private const string AesCryptFileName = "aescrypt";

        public static bool CanAesCryptRun()
        {
            try
            {
                var startInfo = new ProcessStartInfo(AesCryptFileName)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(startInfo);
            }
            catch (Exception exception)
            {
                Debug.WriteLine(exception);
                return false;
            }
            return true;
        }

        public static async Task<bool> CanDecrypt(string fileName, string outputFileName, string password, CancellationToken cancellationToken = default)
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

            try
            {
                var process = Process.Start(AesCryptFileName, $"-d -p {password} -o {outputFileName} {fileName}");
                await process!.WaitForExitAsync(cancellationToken);
                return await Task.FromResult(process.ExitCode == 0);
            }
            catch (Exception exception)
            {
                Debug.WriteLine(exception);
                return await Task.FromResult(false);
            }
        }
    }
}