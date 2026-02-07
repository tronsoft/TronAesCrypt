using System;
using System.IO;
using CommandLine;
using TRONSoft.TronAesCrypt.Core;

namespace TronAesCrypt.Main;

internal static class Program
{
    private static int _bufferSize = 64 * 1024; // multiple of 16

    public static int Main(string[] args)
    {
        return Parser.Default.ParseArguments<Options>(args)
            .MapResult(
                (Options o) => Run(o),
                errs => 1);
    }

    private static int Run(Options o)
    {
        if (!File.Exists(o.File))
        {
            Console.WriteLine(Resources.The_input_file_does_not_exist, o.File);
            return 1;
        }

        var crypt = new AesCrypt();

        try
        {
            if (o.Encrypt)
            {
                crypt.EncryptFile(o.File, o.Output, o.Password, _bufferSize);
            }
            else if (o.Decrypt)
            {
                crypt.DecryptFile(o.File, o.Output, o.Password, _bufferSize);
            }
            else
            {
                Console.WriteLine(Resources.You_must_specify_either_encrypt_or_decrypt_option);
                return 1;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return 1;
        }

        return 0;
    }
}