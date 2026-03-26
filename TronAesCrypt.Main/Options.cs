using System.Collections.Generic;
using CommandLine;
using CommandLine.Text;

namespace TronAesCrypt.Main;

[Verb("aescrypt", isDefault: true, HelpText = "AES-256 file encryption and decryption.")]
public class Options
{
    [Usage(ApplicationAlias = "AesCrypt")]
    public static IEnumerable<Example> Examples =>
    [
        new("Encrypt a file",        new Options { Encrypt = true, Files = ["photo.jpg"],          Password = "secret" }),
        new("Decrypt a file",        new Options { Decrypt = true, Files = ["photo.jpg.aes"],      Password = "secret" }),
        new("Encrypt multiple files",new Options { Encrypt = true, Files = ["a.txt", "b.txt"],     Password = "secret" }),
        new("Generate a key file",   new Options { Generate = true, KeyFile = "secret.key" }),
        new("Encrypt with key file", new Options { Encrypt = true, Files = ["photo.jpg"],          KeyFile = "secret.key" }),
        new("Encrypt stdin to stdout", new Options { Encrypt = true, Files = ["-"], Output = "-",  Password = "secret" }),
    ];

    [Option('e', "encrypt", HelpText = "Encrypt the specified file(s). Mutually exclusive with -d and -g.")]
    public bool Encrypt { get; set; }

    [Option('d', "decrypt", HelpText = "Decrypt the specified file(s). Mutually exclusive with -e and -g.")]
    public bool Decrypt { get; set; }

    [Option('g', "generate", HelpText = "Generate a random key file. Requires -k to specify the output path.")]
    public bool Generate { get; set; }

    [Option('k', "keyfile", Required = false,
        HelpText = "Key file to use as the password (alternative to -p). Generate one with -g -k <path>.")]
    public string? KeyFile { get; set; }

    /// <summary>
    /// Legacy flag-based input. Takes precedence over positional <see cref="Files"/> when both are supplied.
    /// </summary>
    [Option('f', "file", Required = false, Hidden = true,
        HelpText = "Input file path. Deprecated — use a positional argument instead.")]
    public string? LegacyFile { get; set; }

    /// <summary>
    /// Positional input file(s). Ignored when <see cref="LegacyFile"/> is also provided.
    /// </summary>
    [Value(0, MetaName = "file(s)", HelpText = "One or more input files. Use '-' to read from stdin.")]
    public IEnumerable<string> Files { get; set; } = [];

    [Option('o', "output", Required = false,
        HelpText = "Output file path. Omit to auto-generate (encrypt adds .aes; decrypt removes .aes). Use '-' for stdout.")]
    public string? Output { get; set; }

    [Option('p', "password", Required = false,
        HelpText = "Password. Omit to be prompted interactively (input is masked). Cannot be combined with -k.")]
    public string? Password { get; set; }
}