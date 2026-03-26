using System;
using System.Collections.Generic;

namespace TronAesCrypt.Main;

internal static class OptionsExtensions
{
    internal static IEnumerable<string> ResolveInputFiles(this Options options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrEmpty(options.LegacyFile))
        {
            return [options.LegacyFile];
        }

        return options.Files;
    }
}
