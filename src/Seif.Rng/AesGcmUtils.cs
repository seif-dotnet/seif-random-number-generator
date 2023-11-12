namespace Seif.Rng;

public static class AesGcmUtils
{
    /// <summary>
    /// Encrypts the provided plaintext using AES-GCM.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="nonce">The nonce for encryption.</param>
    /// <returns>The encrypted data, combined with the nonce and tag.</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        ValidateParameters(data, key, nonce);

        using var aes = new AesGcm(key);
        byte[] rentedCiphertext = ArrayPool<byte>.Shared.Rent(data.Length);
        byte[] rentedTag = ArrayPool<byte>.Shared.Rent(AesGcm.TagByteSizes.MaxSize);

        try
        {
            var ciphertext = new Span<byte>(rentedCiphertext, 0, data.Length);
            var tag = new Span<byte>(rentedTag, 0, AesGcm.TagByteSizes.MaxSize);
            aes.Encrypt(nonce, data, ciphertext, tag);

            byte[] result = Combine(nonce, ciphertext, tag);

            Array.Clear(rentedCiphertext, 0, data.Length);
            Array.Clear(rentedTag, 0, AesGcm.TagByteSizes.MaxSize);

            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedCiphertext);
            ArrayPool<byte>.Shared.Return(rentedTag);
        }
    }

    /// <summary>
    /// Decrypts the provided data in-place using AES-GCM.
    /// </summary>
    /// <param name="encryptedData">The encrypted data, including nonce and tag.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="nonce">The nonce used for encryption.</param>
    /// <returns>The decrypted plaintext.</returns>
    public static byte[] Decrypt(ReadOnlySpan<byte> encryptedData, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        ValidateParameters(encryptedData, key, nonce);

        using var aes = new AesGcm(key);
        int ciphertextLength = encryptedData.Length - nonce.Length - AesGcm.TagByteSizes.MaxSize;
        byte[] rentedCiphertext = ArrayPool<byte>.Shared.Rent(ciphertextLength);
        byte[] rentedTag = ArrayPool<byte>.Shared.Rent(AesGcm.TagByteSizes.MaxSize);

        try
        {
            var ciphertextSpan = new Span<byte>(rentedCiphertext, 0, ciphertextLength);
            var tagSpan = new Span<byte>(rentedTag, 0, AesGcm.TagByteSizes.MaxSize);

            encryptedData.Slice(nonce.Length, ciphertextLength).CopyTo(ciphertextSpan);
            encryptedData.Slice(encryptedData.Length - AesGcm.TagByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize).CopyTo(tagSpan);

            var plaintext = new byte[ciphertextLength];
            aes.Decrypt(nonce, ciphertextSpan, tagSpan, plaintext);

            return plaintext;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedCiphertext);
            ArrayPool<byte>.Shared.Return(rentedTag);
        }
    }

    private static byte[] Combine(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
        var combined = new byte[nonce.Length + ciphertext.Length + tag.Length];
        var combinedSpan = combined.AsSpan();

        nonce.CopyTo(combinedSpan);
        ciphertext.CopyTo(combinedSpan[nonce.Length..]);
        tag.CopyTo(combinedSpan[(nonce.Length + ciphertext.Length)..]);

        return combined;
    }

    private static void ValidateParameters(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (data.IsEmpty)
        {
            throw new ArgumentException("Invalid data length. Data must not be null or empty.", nameof(data));
        }

        if (key.Length != 32)
        {
            throw new ArgumentException("Invalid key length. Key must be 32 bytes.", nameof(key));
        }

        if (nonce.Length != AesGcm.NonceByteSizes.MaxSize)
        {
            throw new ArgumentException("Invalid nonce length. Nonce must be 12 bytes.", nameof(nonce));
        }
    }
}