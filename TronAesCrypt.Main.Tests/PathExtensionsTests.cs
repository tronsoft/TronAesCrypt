using System;
using Xunit;

namespace TronAesCrypt.Main.Tests;

public class PathExtensionsTests
{
    [Fact]
    public void GetDecryptOutputPath_RemovesAesSuffix_IgnoringCase()
    {
        // Arrange
        const string inputPath = "file.TXT.AES";

        // Act
        var outputPath = inputPath.GetDecryptOutputPath();

        // Assert
        Assert.Equal("file.TXT", outputPath);
    }

    [Fact]
    public void GetDecryptOutputPath_Throws_WhenNoAesSuffixExists()
    {
        // Arrange
        const string inputPath = "file.txt";

        // Act
        void Act() => inputPath.GetDecryptOutputPath();

        // Assert
        Assert.Throws<ArgumentException>(Act);
    }
}
