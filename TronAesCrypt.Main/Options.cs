using CommandLine;

namespace TronAesCrypt.Main;

// Converted to mutable POCO pattern for CommandLineParser
public class Options
{
    [Option('e', "encrypt", HelpText = "Encrypt input file")]
    public bool Encrypt { get; set; }

    [Option('d', "decrypt", HelpText = "Decrypt input file")]
    public bool Decrypt { get; set; }

    [Option('f', "file", Required = true, HelpText = "Input file path")]
    public string File { get; set; } = string.Empty;

    [Option('o', "output", Required = true, HelpText = "Output file path")]
    public string Output { get; set; } = string.Empty;

    [Option('p', "password", Required = true, HelpText = "Password for encryption/decryption")]
    public string Password { get; set; } = string.Empty;
}