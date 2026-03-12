using System.Collections.Generic;
using CommandLine;

namespace TronAesCrypt.Main;

public class Options
{
    [Option('e', "encrypt", HelpText = "Encrypt the input file(s).")]
    public bool Encrypt { get; set; }

    [Option('d', "decrypt", HelpText = "Decrypt the input file(s).")]
    public bool Decrypt { get; set; }

    /// <summary>
    /// Legacy flag-based input. Takes precedence over positional <see cref="Files"/> when both are supplied.
    /// </summary>
    [Option('f', "file", Required = false, HelpText = "Input file path (legacy; prefer positional argument).")]
    public string? LegacyFile { get; set; }

    /// <summary>
    /// Positional input file(s). Ignored when <see cref="LegacyFile"/> is also provided.
    /// </summary>
    [Value(0, MetaName = "files", HelpText = "One or more input file paths.")]
    public IEnumerable<string> Files { get; set; } = [];

    [Option('o', "output", Required = false, HelpText = "Output file path. Omit to auto-generate (appends or removes .aes).")]
    public string? Output { get; set; }

    [Option('p', "password", Required = false, HelpText = "Password. Omit to be prompted interactively.")]
    public string? Password { get; set; }
}