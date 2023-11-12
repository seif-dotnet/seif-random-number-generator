namespace Seif.Rng.Sandbox.Benchmarks;

public static class AesGcmUtilsUnOptimized
{
    public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] nonce)
    {
        ValidateParameters(plaintext, key, nonce);

        using var aes = new AesGcm(key);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var ciphertext = new byte[plaintext.Length];

        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var encryptedData = new byte[nonce.Length + ciphertext.Length + tag.Length];
        nonce.CopyTo(encryptedData, 0);
        ciphertext.CopyTo(encryptedData, nonce.Length);
        tag.CopyTo(encryptedData, nonce.Length + ciphertext.Length);

        return encryptedData;
    }

    public static byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] nonce)
    {
        ValidateParameters(encryptedData, key, nonce);

        using var aes = new AesGcm(key);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        var ciphertext = new byte[encryptedData.Length - nonce.Length - tag.Length];
        Array.Copy(encryptedData, nonce.Length, ciphertext, 0, ciphertext.Length);
        Array.Copy(encryptedData, encryptedData.Length - tag.Length, tag, 0, tag.Length);

        var plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    private static void ValidateParameters(byte[] data, byte[] key, byte[] nonce)
    {
        if (data is null || data.Length == 0)
        {
            throw new ArgumentException("Invalid data length. Data must not be null or empty.", nameof(data));
        }

        if (key is null || key.Length != 32)
        {
            throw new ArgumentException("Invalid key length. Key must be 32 bytes.", nameof(key));
        }

        if (nonce == null || nonce.Length != AesGcm.NonceByteSizes.MaxSize)
        {
            throw new ArgumentException("Invalid nonce length. Nonce must be 12 bytes.", nameof(nonce));
        }
    }
}