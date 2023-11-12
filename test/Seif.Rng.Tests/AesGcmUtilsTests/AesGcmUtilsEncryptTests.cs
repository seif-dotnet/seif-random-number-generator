#pragma warning disable CA1024 // Disable warning for static method

namespace Seif.Rng.Tests.AesGcmUtilsTests;

public class AesGcmUtilsEncryptTests
{
    private readonly byte[] _validKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _validNonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
    private readonly byte[] _validData = EncryptionTestData.ShortByteData;

    [Theory]
    [MemberData(nameof(GetByteTestData))]
    public void Should_Encrypt_And_Decrypt_To_Original_Byte_Array(byte[] testData)
    {
        byte[] encrypted = AesGcmUtils.Encrypt(testData, _validKey, _validNonce);
        byte[] decrypted = AesGcmUtils.Decrypt(encrypted, _validKey, _validNonce);

        decrypted.Should().BeEquivalentTo(testData);
    }

    [Theory]
    [MemberData(nameof(GetTextTestData))]
    public void Should_Encrypt_And_Decrypt_To_Original_Text(string testData)
    {
        byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);

        byte[] encrypted = AesGcmUtils.Encrypt(testDataBytes, _validKey, _validNonce);
        byte[] decrypted = AesGcmUtils.Decrypt(encrypted, _validKey, _validNonce);

        string decryptedText = Encoding.UTF8.GetString(decrypted);

        decryptedText.Should().BeEquivalentTo(testData);
    }

    [Fact]
    public void Should_Throw_ArgumentException_For_Invalid_Key_Length()
    {
        byte[] key = RandomNumberGenerator.GetBytes(31);

        Action encryptAction = () => AesGcmUtils.Encrypt(_validData, key, _validNonce);

        encryptAction.Should().Throw<ArgumentException>().WithMessage("*key length*");
    }

    [Fact]
    public void Should_Throw_ArgumentException_For_Invalid_Nonce_Length()
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(11);

        Action encryptAction = () => AesGcmUtils.Encrypt(_validData, _validKey, nonce);

        encryptAction.Should().Throw<ArgumentException>().WithMessage("*nonce length*");
    }

    [Fact]
    public void Should_Throw_ArgumentException_For_Empty_Data()
    {
        byte[] data = Array.Empty<byte>();

        Action encryptAction = () => AesGcmUtils.Encrypt(data, _validKey, _validNonce);

        encryptAction.Should().Throw<ArgumentException>().WithMessage("*data length*");
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