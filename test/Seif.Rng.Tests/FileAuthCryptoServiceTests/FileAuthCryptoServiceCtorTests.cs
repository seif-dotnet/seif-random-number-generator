#pragma warning disable CA1806, CS8625 // Disable warning for unused variables and nullable reference type

namespace Seif.Rng.Tests.FileAuthCryptoServiceTests;

public class FileAuthCryptoServiceCtorTests
{
    [Fact]
    public void Should_Create_Instance_Of_FileAuthCryptoService_With_Default_FileSystem()
    {
        var service = new FileAuthCryptoService();

        service.Should().BeOfType<FileAuthCryptoService>();
    }

    [Fact]
    public void Should_Create_Instance_Of_FileAuthCryptoService_With_FileSystem()
    {
        var mockFileSystem = new MockFileSystem();
        var service = new FileAuthCryptoService(mockFileSystem);

        service.Should().BeOfType<FileAuthCryptoService>();
    }

    [Fact]
    public void Should_Throw_ArgumentNullException_When_FileSystem_Is_Null()
    {
        Action act = () => new FileAuthCryptoService(fileSystem: null);

        act.Should().Throw<ArgumentNullException>().WithMessage("*fileSystem*");
    }
}