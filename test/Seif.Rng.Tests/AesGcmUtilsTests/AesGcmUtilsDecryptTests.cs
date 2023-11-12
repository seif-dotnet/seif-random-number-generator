namespace Seif.Rng.Tests.AesGcmUtilsTests;

public class AesGcmUtilsDecryptTests
{
    private readonly byte[] _validKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _validNonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
    private readonly byte[] _validData = EncryptionTestData.ShortByteData;

    [Theory]
    [MemberData(nameof(GetByteTestData))]
    public void Should_Decrypt_Encrypted_Byte_Array_To_Original(byte[] testData)
    {
        byte[] encrypted = AesGcmUtils.Encrypt(testData, _validKey, _validNonce);
        byte[] decrypted = AesGcmUtils.Decrypt(encrypted, _validKey, _validNonce);

        decrypted.Should().BeEquivalentTo(testData);
    }

    [Theory]
    [MemberData(nameof(GetTextTestData))]
    public void Should_Decrypt_Encrypted_Text_To_Original(string testData)
    {
        byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);
        byte[] encrypted = AesGcmUtils.Encrypt(testDataBytes, _validKey, _validNonce);
        byte[] decrypted = AesGcmUtils.Decrypt(encrypted, _validKey, _validNonce);

        string decryptedText = Encoding.UTF8.GetString(decrypted);

        decryptedText.Should().BeEquivalentTo(testData);
    }

    [Fact]
    public void Should_Throw_ArgumentException_For_Invalid_Key_Length_On_Decrypt()
    {
        byte[] key = RandomNumberGenerator.GetBytes(31); // Invalid key length
        byte[] encryptedData = AesGcmUtils.Encrypt(_validData, _validKey, _validNonce);

        Action decryptAction = () => AesGcmUtils.Decrypt(encryptedData, key, _validNonce);

        decryptAction.Should().Throw<ArgumentException>().WithMessage("*key length*");
    }

    [Fact]
    public void Should_Throw_ArgumentException_For_Invalid_Nonce_Length_On_Decrypt()
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(11); // Invalid nonce length
        byte[] encryptedData = AesGcmUtils.Encrypt(_validData, _validKey, _validNonce);

        Action decryptAction = () => AesGcmUtils.Decrypt(encryptedData, _validKey, nonce);

        decryptAction.Should().Throw<ArgumentException>().WithMessage("*nonce length*");
    }

    [Fact]
    public void Should_Throw_ArgumentException_For_Empty_EncryptedData_On_Decrypt()
    {
        byte[] emptyEncryptedData = Array.Empty<byte>();

        Action decryptAction = () => AesGcmUtils.Decrypt(emptyEncryptedData, _validKey, _validNonce);

        decryptAction.Should().Throw<ArgumentException>().WithMessage("*data length*");
    }

    [Fact]
    public void Should_Fail_Decryption_With_Corrupted_Data()
    {
        byte[] originalData = EncryptionTestData.ShortByteData;
        byte[] encrypted = AesGcmUtils.Encrypt(originalData, _validKey, _validNonce);

        // Corrupting the encrypted data by changing some bytes
        encrypted[10] ^= 0xff;
        encrypted[20] ^= 0xff;

        Action decryptAction = () => AesGcmUtils.Decrypt(encrypted, _validKey, _validNonce);

        decryptAction.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Should_Fail_Decryption_With_Incorrect_Key()
    {
        byte[] encrypted = AesGcmUtils.Encrypt(_validData, _validKey, _validNonce);
        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);

        Action decryptAction = () => AesGcmUtils.Decrypt(encrypted, wrongKey, _validNonce);

        decryptAction.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Should_Fail_Decryption_With_Incorrect_Nonce()
    {
        byte[] encrypted = AesGcmUtils.Encrypt(_validData, _validKey, _validNonce);
        byte[] wrongNonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);

        Action decryptAction = () => AesGcmUtils.Decrypt(encrypted, _validKey, wrongNonce);

        decryptAction.Should().Throw<CryptographicException>();
    }

    public static IEnumerable<object[]> GetTextTestData()
    {
        return AesGcmUtilsEncryptTests.GetTextTestData();
    }

    public static IEnumerable<object[]> GetByteTestData()
    {
        return AesGcmUtilsEncryptTests.GetByteTestData();
    }
}