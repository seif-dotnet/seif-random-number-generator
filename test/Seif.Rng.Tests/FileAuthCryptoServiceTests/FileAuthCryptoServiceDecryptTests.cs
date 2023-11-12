#pragma warning disable CA1024, CS8625 // Disable warning for static method and nullable reference type

namespace Seif.Rng.Tests.FileAuthCryptoServiceTests;

public class FileAuthCryptoServiceDecryptTests
{
    private readonly FileAuthCryptoService _service;
    private readonly MockFileSystem _mockFileSystem;
    private readonly byte[] _validKey;
    private readonly byte[] _validNonce;

    public FileAuthCryptoServiceDecryptTests()
    {
        _mockFileSystem = new MockFileSystem();
        _service = new FileAuthCryptoService(_mockFileSystem);
        _validKey = RandomNumberGenerator.GetBytes(32);
        _validNonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
    }

    [Theory]
    [MemberData(nameof(GetTextTestData))]
    public async Task DecryptFileAsync_Should_Decrypt_TextFile_Async(string textData)
    {
        const string filename = @"c:\testfile.txt";
        byte[] encryptedData = AesGcmUtils.Encrypt(Encoding.UTF8.GetBytes(textData), _validKey, _validNonce);
        _mockFileSystem.AddFile(filename, new MockFileData(encryptedData));

        await _service.DecryptFileAsync(filename, _validKey, _validNonce).ConfigureAwait(false);

        string decryptedText = Encoding.UTF8.GetString(_mockFileSystem.GetFile(filename).Contents);
        decryptedText.Should().Be(textData);
    }

    [Theory]
    [MemberData(nameof(GetByteTestData))]
    public async Task DecryptFileAsync_Should_Decrypt_BinaryFile_Async(byte[] byteData)
    {
        const string filename = @"c:\testfile.bin";
        byte[] encryptedData = AesGcmUtils.Encrypt(byteData, _validKey, _validNonce);
        _mockFileSystem.AddFile(filename, new MockFileData(encryptedData));

        await _service.DecryptFileAsync(filename, _validKey, _validNonce).ConfigureAwait(false);

        byte[] decryptedData = _mockFileSystem.GetFile(filename).Contents;
        decryptedData.Should().BeEquivalentTo(byteData);
    }

    [Fact]
    public async Task DecryptFileAsync_With_Invalid_Filename_Should_Throw_ArgumentException_Async()
    {
        var act = async () => await _service.DecryptFileAsync(filename: null, _validKey, _validNonce).ConfigureAwait(false);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("Filename must not be null or empty.*").ConfigureAwait(false);
    }

    [Fact]
    public async Task DecryptFileAsync_With_Invalid_Key_Should_Throw_ArgumentException_Async()
    {
        var act = async () => await _service.DecryptFileAsync(@"c:\testfile.txt", Array.Empty<byte>(), _validNonce).ConfigureAwait(false);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("Invalid key length. Key must be 32 bytes.*").ConfigureAwait(false);
    }

    [Fact]
    public async Task DecryptFileAsync_With_Invalid_Nonce_Should_Throw_ArgumentException_Async()
    {
        var act = async () => await _service.DecryptFileAsync(@"c:\testfile.txt", _validKey, Array.Empty<byte>()).ConfigureAwait(false);

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("Invalid nonce length. Nonce must be 12 bytes.*").ConfigureAwait(false);
    }

    [Fact]
    public async Task DecryptFileAsync_With_Non_Existent_File_ShouldThrowFileNotFoundException_Async()
    {
        const string filename = @"c:\nonexistentfile.txt";

        var act = async () => await _service.DecryptFileAsync(filename, _validKey, _validNonce).ConfigureAwait(false);

        await act.Should().ThrowAsync<FileNotFoundException>()
            .WithMessage("File to be decrypted not found.*").ConfigureAwait(false);
    }

    [Theory]
    [MemberData(nameof(GetTextTestData))]
    public void DecryptFile_Should_Decrypt_TextFile(string textData)
    {
        const string filename = @"c:\testfile.txt";
        byte[] encryptedData = AesGcmUtils.Encrypt(Encoding.UTF8.GetBytes(textData), _validKey, _validNonce);
        _mockFileSystem.AddFile(filename, new MockFileData(encryptedData));

        _service.DecryptFile(filename, _validKey, _validNonce);

        string decryptedText = Encoding.UTF8.GetString(_mockFileSystem.GetFile(filename).Contents);
        decryptedText.Should().Be(textData);
    }

    [Theory]
    [MemberData(nameof(GetByteTestData))]
    public void DecryptFile_Should_Decrypt_BinaryFile(byte[] byteData)
    {
        const string filename = @"c:\testfile.bin";
        byte[] encryptedData = AesGcmUtils.Encrypt(byteData, _validKey, _validNonce);
        _mockFileSystem.AddFile(filename, new MockFileData(encryptedData));

        _service.DecryptFile(filename, _validKey, _validNonce);

        byte[] decryptedData = _mockFileSystem.GetFile(filename).Contents;
        decryptedData.Should().BeEquivalentTo(byteData);
    }

    [Fact]
    public void DecryptFile_With_Invalid_Filename_Should_Throw_ArgumentException()
    {
        Action act = () => _service.DecryptFile(filename: null, _validKey, _validNonce);

        act.Should().Throw<ArgumentException>()
            .WithMessage("Filename must not be null or empty.*");
    }

    [Fact]
    public void DecryptFile_With_Invalid_Key_Should_Throw_ArgumentException()
    {
        Action act = () => _service.DecryptFile(@"c:\testfile.txt", Array.Empty<byte>(), _validNonce);

        act.Should().Throw<ArgumentException>()
            .WithMessage("Invalid key length. Key must be 32 bytes.*");
    }

    [Fact]
    public void DecryptFile_With_Invalid_Nonce_Should_Throw_ArgumentException()
    {
        Action act = () => _service.DecryptFile(@"c:\testfile.txt", _validKey, Array.Empty<byte>());

        act.Should().Throw<ArgumentException>()
            .WithMessage("Invalid nonce length. Nonce must be 12 bytes.*");
    }

    [Fact]
    public void DecryptFile_With_Non_Existent_File_ShouldThrowFileNotFoundException()
    {
        const string filename = @"c:\nonexistentfile.txt";

        Action act = () => _service.DecryptFile(filename, _validKey, _validNonce);

        act.Should().Throw<FileNotFoundException>()
            .WithMessage("File to be decrypted not found.*");
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