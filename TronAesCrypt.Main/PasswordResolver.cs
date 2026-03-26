using System;
using System.IO;
using System.Text;

namespace TronAesCrypt.Main;

internal sealed class PasswordResolver(ICryptEnvironment env)
{
    internal string Resolve(Options options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrEmpty(options.Password))
        {
            return options.Password;
        }

        if (!string.IsNullOrEmpty(options.KeyFile))
        {
            if (!File.Exists(options.KeyFile))
            {
                throw new FileNotFoundException(string.Format(Resources.Key_file_not_found, options.KeyFile));
            }

            using var stream = env.OpenInput(options.KeyFile, false);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return reader.ReadToEnd();
        }

        return env.ReadPassword();
    }
}
