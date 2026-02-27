using System;
using System.IO;
using CommandLine;
using TronAesCrypt.Main;
using TRONSoft.TronAesCrypt.Core;

const int bufferSize = 64 * 1024;

return Parser.Default
    .ParseArguments<Options>(args)
    .MapResult(Run, _ => 1);

int Run(Options options)
{
    if (!File.Exists(options.File))
    {
        Console.WriteLine(Resources.The_input_file_does_not_exist, options.File);
        return 1;
    }

    var crypt = new AesCrypt();

    try
    {
        if (options.Encrypt)
        {
            crypt.EncryptFile(options.File, options.Output, options.Password, bufferSize);
        }
        else if (options.Decrypt)
        {
            crypt.DecryptFile(options.File, options.Output, options.Password, bufferSize);
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