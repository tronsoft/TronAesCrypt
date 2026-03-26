using System;

namespace TronAesCrypt.Main;

internal static class PathExtensions
{
    internal static string GetDecryptOutputPath(this string inputFile)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputFile);

        if (inputFile.EndsWith(".aes", StringComparison.OrdinalIgnoreCase))
        {
            return inputFile[..^4];
        }

        throw new ArgumentException(string.Format(Resources.Cannot_auto_determine_output_file, inputFile));
    }
}
