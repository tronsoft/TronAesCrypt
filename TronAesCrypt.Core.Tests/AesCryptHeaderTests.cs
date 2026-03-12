using System;
using System.IO;
using System.Reflection;
using Xunit;

namespace TRONSoft.TronAesCrypt.Core.Tests;

public class AesCryptHeaderTests
{
    [Fact]
    public void WriteHeader_WithoutKdfIterations_ThrowsNotSupportedException()
    {
        // Arrange
        var header = new AesCryptHeader();
        using var stream = new MemoryStream();

        // Act & Assert
        // We must invoke via reflection because the method is marked [Obsolete(..., error: true)]
        // preventing the test from compiling if called directly. This proves the runtime guard works
        // for consumers who might execute this using an older compiled binary against the new DLL.
        var method = typeof(AesCryptHeader).GetMethod("WriteHeader", new[] { typeof(Stream) });
        var ex = Assert.Throws<TargetInvocationException>(() => method.Invoke(header, new object[] { stream }));
        Assert.IsType<NotSupportedException>(ex.InnerException);
    }

    [Fact]
    public void WriteHeader_WithKdfIterations_WritesV3HeaderExtensionsAndIterations()
    {
        // Arrange
        var header = new AesCryptHeader();
        using var stream = new MemoryStream();
        var expectedIterations = 300000;

        // Act
        header.WriteHeader(stream, expectedIterations);

        // Assert
        stream.Position = 0;
        
        // ReadHeader consumes the magic marker, version, reserved byte, and extension segments
        var version = header.ReadHeader(stream);
        Assert.Equal(AesCryptVersion.V3, version);

        // Read the extra 4 bytes containing KDF iteration counts
        var iterationBytes = new byte[4];
        var bytesRead = stream.Read(iterationBytes, 0, iterationBytes.Length);
        
        Assert.Equal(4, bytesRead);
        
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(iterationBytes);
        }
        
        var actualIterations = BitConverter.ToInt32(iterationBytes, 0);
        Assert.Equal(expectedIterations, actualIterations);
        
        // We should now be completely at the end of the written header contents
        Assert.Equal(stream.Length, stream.Position);
    }
}
