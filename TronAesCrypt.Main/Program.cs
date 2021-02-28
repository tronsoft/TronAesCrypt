using System;
using System.IO;
using CommandLine;
using TRONSoft.TronAesCrypt.Core;

namespace TronAesCrypt.Main
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed(o =>
            {
                if (!File.Exists(o.FileName))
                {
                    Console.WriteLine(Resources.The_input_file_does_not_exist, o.FileName);
                    Environment.ExitCode = 1;
                    return;
                }

                if (o.Encrypt)
                {
                    var crypt = new AesCrypt();
                    crypt.EncryptFile(o.FileName, o.OutputFile, o.Password);
                }
                else if (o.Decrypt)
                {
                    var crypt = new AesCrypt();
                    crypt.DecryptFile(o.FileName, o.OutputFile, o.Password);
                }
            });
        }
    }
}
