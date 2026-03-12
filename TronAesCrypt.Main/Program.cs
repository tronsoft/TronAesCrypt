using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CommandLine;
using TronAesCrypt.Main;
using TRONSoft.TronAesCrypt.Core;

const int bufferSize = 64 * 1024;

return Parser.Default
    .ParseArguments<Options>(args)
    .MapResult(Run, _ => 1);

int Run(Options options)
{
    if (!options.Encrypt && !options.Decrypt)
    {
        Console.WriteLine(Resources.You_must_specify_either_encrypt_or_decrypt_option);
        return 1;
    }

    var inputFiles = ResolveInputFiles(options);
    if (inputFiles is null)
    {
        return 1;
    }

    var password = options.Password;
    if (string.IsNullOrEmpty(password))
    {
        Console.WriteLine(Resources.You_must_specify_a_password);
        return 1;
    }

    var crypt = new AesCrypt();
    var exitCode = 0;

    foreach (var inputFile in inputFiles)
    {
        if (!File.Exists(inputFile))
        {
            Console.WriteLine(Resources.The_input_file_does_not_exist, inputFile);
            exitCode = 1;
            continue;
        }

        var outputFile = ResolveOutputFile(options, inputFile);
        if (outputFile is null)
        {
            exitCode = 1;
            continue;
        }

        try
        {
            if (options.Encrypt)
            {
                crypt.EncryptFile(inputFile, outputFile, password, bufferSize);
            }
            else
            {
                crypt.DecryptFile(inputFile, outputFile, password, bufferSize);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            exitCode = 1;
        }
    }

    return exitCode;
}

/// <summary>
/// Resolves the list of input files from options.
/// The legacy -f flag takes precedence over positional arguments.
/// Returns null and prints an error if no input file can be determined.
/// </summary>
IEnumerable<string>? ResolveInputFiles(Options options)
{
    var hasLegacyFile = !string.IsNullOrEmpty(options.LegacyFile);
    var positionalFiles = options.Files.ToList();
    var hasPositional = positionalFiles.Count > 0;

    if (hasLegacyFile && hasPositional)
    {
        Console.WriteLine(Resources.Do_not_mix_f_flag_with_positional_arguments);
        return null;
    }

    if (hasLegacyFile)
    {
        return [options.LegacyFile!];
    }

    if (hasPositional)
    {
        return positionalFiles;
    }

    Console.WriteLine(Resources.You_must_specify_an_input_file);
    return null;
}

/// <summary>
/// Resolves the output file path. Uses the explicit -o value if provided;
/// otherwise auto-generates based on the input file name and mode.
/// </summary>
string? ResolveOutputFile(Options options, string inputFile)
{
    if (!string.IsNullOrEmpty(options.Output))
    {
        return options.Output;
    }

    return options.Encrypt
        ? inputFile + ".aes"
        : GetDecryptOutputPath(inputFile);
}

/// <summary>
/// Removes the .aes extension from the input path for auto-generated decrypt output.
/// </summary>
string? GetDecryptOutputPath(string inputFile)
{
    if (inputFile.EndsWith(".aes", StringComparison.OrdinalIgnoreCase))
    {
        return inputFile[..^4];
    }

    Console.WriteLine(Resources.Cannot_auto_determine_output_file, inputFile);
    return null;
}