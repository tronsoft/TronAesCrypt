using System.IO;
using System.Text;
using Xunit;

namespace TronAesCrypt.Main.Tests;

public class PasswordResolverTests
{
    [Fact]
    public void Resolve_ReturnsPassword_WhenPasswordOptionIsProvided()
    {
        // Arrange
        var resolver = new PasswordResolver(new TestEnvironment(passwordReader: () => "prompt"));
        var options = new Options { Password = "from-option" };

        // Act
        var resolved = resolver.Resolve(options);

        // Assert
        Assert.Equal("from-option", resolved);
    }

    [Fact]
    public void Resolve_ReturnsPromptPassword_WhenNoPasswordOrKeyFileIsProvided()
    {
        // Arrange
        var resolver = new PasswordResolver(new TestEnvironment(passwordReader: () => "from-prompt"));
        var options = new Options();

        // Act
        var resolved = resolver.Resolve(options);

        // Assert
        Assert.Equal("from-prompt", resolved);
    }

    [Fact]
    public void Resolve_Throws_WhenKeyFileDoesNotExist()
    {
        // Arrange
        var resolver = new PasswordResolver(new TestEnvironment());
        var options = new Options { KeyFile = "missing.key" };

        // Act
        void Act() => resolver.Resolve(options);

        // Assert
        Assert.Throws<FileNotFoundException>(Act);
    }

    [Fact]
    public void Resolve_ReadsPasswordFromKeyFile_WhenKeyFileExists()
    {
        // Arrange
        var keyFile = Path.GetTempFileName();
        File.WriteAllText(keyFile, "from-key-file", Encoding.UTF8);

        try
        {
            var resolver = new PasswordResolver(new TestEnvironment());
            var options = new Options { KeyFile = keyFile };

            // Act
            var resolved = resolver.Resolve(options);

            // Assert
            Assert.Equal("from-key-file", resolved);
        }
        finally
        {
            File.Delete(keyFile);
        }
    }
}
