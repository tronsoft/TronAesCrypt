using System;
using Xunit;

namespace TronAesCrypt.Main.Tests;

public class OptionsValidatorTests
{
    [Fact]
    public void ValidateOrThrow_Throws_WhenNoOperationIsSpecified()
    {
        // Arrange
        var options = new Options();

        // Act
        void Act() => OptionsValidator.ValidateOrThrow(options);

        // Assert
        Assert.Throws<ArgumentException>(Act);
    }

    [Fact]
    public void ValidateOrThrow_Throws_WhenGenerateWithoutKeyFile()
    {
        // Arrange
        var options = new Options
        {
            Generate = true,
        };

        // Act
        void Act() => OptionsValidator.ValidateOrThrow(options);

        // Assert
        Assert.Throws<ArgumentException>(Act);
    }

    [Fact]
    public void ValidateOrThrow_Throws_WhenPasswordAndKeyFileAreBothProvided()
    {
        // Arrange
        var options = new Options
        {
            Encrypt = true,
            Files = ["input.txt"],
            Password = "password",
            KeyFile = "secret.key",
        };

        // Act
        void Act() => OptionsValidator.ValidateOrThrow(options);

        // Assert
        Assert.Throws<ArgumentException>(Act);
    }

    [Fact]
    public void ValidateOrThrow_DoesNotThrow_ForValidEncryptOptions()
    {
        // Arrange
        var options = new Options
        {
            Encrypt = true,
            Files = ["input.txt"],
            Password = "password",
        };

        // Act
        var exception = Record.Exception(() => OptionsValidator.ValidateOrThrow(options));

        // Assert
        Assert.Null(exception);
    }
}
