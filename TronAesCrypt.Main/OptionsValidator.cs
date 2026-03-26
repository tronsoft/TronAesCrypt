using System;
using System.Linq;
using ArgumentNullException = System.ArgumentNullException;

namespace TronAesCrypt.Main;

internal static class OptionsValidator
{
    internal static void ValidateOrThrow(Options options)
    {
        ArgumentNullException.ThrowIfNull(options);

        bool[] cryptoOptionsStatus = [options.Encrypt, options.Decrypt, options.Generate];
        var operationCount = cryptoOptionsStatus.Count(enabled => enabled);
        if (operationCount == 0)
        {
            throw new ArgumentException(Resources.You_must_specify_either_encrypt_or_decrypt_option);
        }

        if (operationCount > 1)
        {
            throw new ArgumentException(Resources.Cannot_use_multiple_operations);
        }

        if (!string.IsNullOrEmpty(options.Password) && !string.IsNullOrEmpty(options.KeyFile))
        {
            throw new ArgumentException(Resources.Cannot_use_both_password_and_keyfile);
        }

        if (options.Generate)
        {
            ValidateGenerateOptions(options);
        }
        else
        {
            ValidateCryptOptions(options);
        }
    }

    private static void ValidateGenerateOptions(Options options)
    {
        if (string.IsNullOrEmpty(options.KeyFile))
        {
            throw new ArgumentException(Resources.Key_file_path_required);
        }
    }

    private static void ValidateCryptOptions(Options options)
    {
        if (!string.IsNullOrEmpty(options.LegacyFile) && options.Files.Any())
        {
            throw new ArgumentException(Resources.Do_not_mix_f_flag_with_positional_arguments);
        }

        var files = options.ResolveInputFiles().ToList();
        if (files.Count == 0)
        {
            throw new ArgumentException(Resources.You_must_specify_an_input_file);
        }

        var stdinCount = files.Count(file => file == "-");
        if (stdinCount > 1)
        {
            throw new ArgumentException(Resources.Cannot_use_multiple_stdin);
        }

        if (stdinCount == 1)
        {
            if (files.Count > 1)
            {
                throw new ArgumentException(Resources.Cannot_mix_stdin_with_positional);
            }

            if (string.IsNullOrEmpty(options.Output))
            {
                throw new ArgumentException(Resources.Stdin_requires_explicit_output);
            }
        }

        if (!string.IsNullOrEmpty(options.Output) && options.Output != "-" && files.Count > 1)
        {
            throw new ArgumentException(Resources.Cannot_use_o_with_multiple_files);
        }
    }
}
