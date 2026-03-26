using System.Linq;
using Xunit;

namespace TronAesCrypt.Main.Tests;

public class OptionsExtensionsTests
{
    [Fact]
    public void ResolveInputFiles_UsesLegacyFile_WhenProvided()
    {
        // Arrange
        var options = new Options
        {
            LegacyFile = "legacy.txt",
            Files = ["positional.txt"],
        };

        // Act
        var resolvedFiles = options.ResolveInputFiles().ToList();

        // Assert
        Assert.Single(resolvedFiles);
        Assert.Equal("legacy.txt", resolvedFiles[0]);
    }

    [Fact]
    public void ResolveInputFiles_UsesPositionalFiles_WhenLegacyFileMissing()
    {
        // Arrange
        var options = new Options
        {
            Files = ["a.txt", "b.txt"],
        };

        // Act
        var resolvedFiles = options.ResolveInputFiles().ToList();

        // Assert
        Assert.Equal(2, resolvedFiles.Count);
        Assert.Equal("a.txt", resolvedFiles[0]);
        Assert.Equal("b.txt", resolvedFiles[1]);
    }
}
