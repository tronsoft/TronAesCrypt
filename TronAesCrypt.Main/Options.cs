using System.Collections.Generic;
using CommandLine;
using CommandLine.Text;

namespace TronAesCrypt.Main;

internal sealed class Options
{
    [Option('e', "encrypt", Default = true, HelpText = "Encrypt a file", SetName = "mode")]
    public bool Encrypt { get; set; }

    [Option('d', "decrypt", HelpText = "Decrypt a file", SetName = "mode")]
    public bool Decrypt { get; set; }

    [Option('o', "output", HelpText = "The encrypted or decrypted file", Required = true)]
    public string OutputFile { get; set; }

    // [Value(0, Default = null, Required = true, HelpText = "The name of the file to encrypt or decrypt", MetaName = "File name")]
    [Option('f', "file", Required = true, HelpText = "The name of the file to encrypt or decrypt")]
    public string FileName { get; set; }

    [Option('p', "password", HelpText = "Password", SetName = "mode", Required = true)]
    public string Password { get; set; }

    [Usage(ApplicationAlias = "AesCrypt.exe")]
    public static IEnumerable<Example> Examples
    {
        get
        {
            yield return new Example("Encrypting a file", new Options { Encrypt = true, OutputFile = "ToEncrypted.txt.aes", FileName = "ToEncrypted.txt", Password = "Password1234" });
            yield return new Example("Decrypting a file", new Options { Decrypt = true, OutputFile = "Encrypted.txt", FileName = "Encrypted.txt.aes", Password = "Password1234" });
        }
    }
}