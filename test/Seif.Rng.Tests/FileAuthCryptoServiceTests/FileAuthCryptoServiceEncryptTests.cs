#pragma warning disable CA1024, CS8625 // Disable warning for static method and nullable reference type

namespace Seif.Rng.Tests.FileAuthCryptoServiceTests;

public class FileAuthCryptoServiceEncryptTests
{
    private readonly FileAuthCryptoService _service;
    private readonly MockFileSystem _mockFileSystem;
    private readonly byte[] _validKey;
    private readonly byte[] _validNonce;

    public FileAuthCryptoServiceEncryptTests()
    {
        _mockFileSystem = new MockFileSystem();
        _service = new FileAuthCryptoService(_mockFileSystem);
        _validKey = RandomNumberGenerator.GetBytes(32);
        _validNonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
    }

    [Theory]
    [MemberData(nameof(GetTextTestData))]
    public async Task EncryptFileAsync_Should_Encrypt_TextFile_Async(string textData)
    {
        const string filename = @"c:\testfile.txt";
        _mockFileSystem.AddFile(filename, new MockFileData(textData));

        await _service.EncryptFileAsync(filename, _validKey, _validNonce).ConfigureAwait(false);

        byte[]? encryptedData = _mockFileSystem.GetFile(filename).Contents;
        byte[] byteData = Encoding.UTF8.GetBytes(textData);

        encryptedData.Should().NotEqual(byteData, "file should be encrypted");
    }

    [Theory]
    [MemberData(nameof(GetByteTestData))]
    public async Task EncryptFileAsync_Should_Encrypt_BinaryFile_Async(byte[] byteData)
    {
        const string filename = @"c:\testfile.bin";
        _mockFileSystem.AddFile(filename, new MockFileData(byteData));

        await _service.EncryptFileAsync(filename, _validKey, _validNonce).ConfigureAwait(false);

        byte[]? encryptedData = _mockFileSystem.GetFile(filename).Contents;
        encryptedData.Should().NotEqual(byteData, "file should be encrypted");
    }

    [Fact]
    public async Task EncryptFileAsync_With_Invalid_Filename_Should_Throw_ArgumentException_Async()
    {
        var act = async () => await _service.EncryptFileAsync(filename: null, _validKey, _validNonce).ConfigureAwait(false);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("Filename must not be null or empty.*").ConfigureAwait(false);
    }

    [Fact]
    public async Task EncryptFileAsync_With_Invalid_Key_Should_Throw_ArgumentException_Async()
    {
        var act = async () =>  await _service.EncryptFileAsync(@"c:\testfile.txt", Array.Empty<byte>(), _validNonce).ConfigureAwait(false);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("Invalid key length. Key must be 32 bytes.*").ConfigureAwait(false);
    }

    [Fact]
    public async Task EncryptFileAsync_With_Invalid_Nonce_Should_Throw_ArgumentException_Async()
    {
        var act = async () => await _service.EncryptFileAsync(@"c:\testfile.txt", _validKey, Array.Empty<byte>()).ConfigureAwait(false);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("Invalid nonce length. Nonce must be 12 bytes.*").ConfigureAwait(false);
    }

    [Theory]
    [MemberData(nameof(GetTextTestData))]
    public void EncryptFile_Should_Encrypt_TextFile(string textData)
    {
        const string filename = @"c:\testfile.txt";
        _mockFileSystem.AddFile(filename, new MockFileData(textData));

        _service.EncryptFile(filename, _validKey, _validNonce);

        byte[]? encryptedData = _mockFileSystem.GetFile(filename).Contents;
        byte[] byteData = Encoding.UTF8.GetBytes(textData);

        encryptedData.Should().NotEqual(byteData, "file should be encrypted");
    }

    [Theory]
    [MemberData(nameof(GetByteTestData))]
    public void EncryptFile_Should_Encrypt_BinaryFile(byte[] byteData)
    {
        const string filename = @"c:\testfile.bin";
        _mockFileSystem.AddFile(filename, new MockFileData(byteData));

        _service.EncryptFile(filename, _validKey, _validNonce);

        byte[]? encryptedData = _mockFileSystem.GetFile(filename).Contents;
        encryptedData.Should().NotEqual(byteData, "file should be encrypted");
    }

    [Fact]
    public void EncryptFile_With_Invalid_Filename_Should_Throw_ArgumentException()
    {
        Action act = () => _service.EncryptFile(filename: null, _validKey, _validNonce);

        act.Should().Throw<ArgumentException>()
            .WithMessage("Filename must not be null or empty.*");
    }

    [Fact]
    public void EncryptFile_With_Invalid_Key_Should_Throw_ArgumentException()
    {
        Action act = () => _service.EncryptFile(@"c:\testfile.txt", Array.Empty<byte>(), _validNonce);

        act.Should().Throw<ArgumentException>()
            .WithMessage("Invalid key length. Key must be 32 bytes.*");
    }

    [Fact]
    public void EncryptFile_With_Invalid_Nonce_Should_Throw_ArgumentException()
    {
        Action act = () => _service.EncryptFile(@"c:\testfile.txt", _validKey, Array.Empty<byte>());

        act.Should().Throw<ArgumentException>()
            .WithMessage("Invalid nonce length. Nonce must be 12 bytes.*");
    }

    public static IEnumerable<object[]> GetTextTestData()
    {
        yield return new object[] { EncryptionTestData.ShortTextData };
        yield return new object[] { EncryptionTestData.LongTextData };
    }

    public static IEnumerable<object[]> GetByteTestData()
    {
        yield return new object[] { EncryptionTestData.ShortByteData };
        yield return new object[] { EncryptionTestData.LongByteData };
    }
}