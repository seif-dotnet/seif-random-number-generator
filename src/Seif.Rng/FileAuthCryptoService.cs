namespace Seif.Rng;

/// <summary>
/// Provides authenticated encryption and decryption services for files using AES-GCM.
/// </summary>
public class FileAuthCryptoService
{
    private readonly IFileSystem _fileSystem;

    public FileAuthCryptoService(IFileSystem fileSystem)
    {
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
    }

    public FileAuthCryptoService() : this(new FileSystem())
    {
    }

    /// <summary>
    /// Asynchronously encrypts a file using AES-GCM, providing authenticated encryption.
    /// </summary>
    /// <param name="filename">The name of the file to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="nonce">The nonce for encryption.</param>
    /// <param name="outputFilePath">The output file path. If null, the original file is overwritten.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task EncryptFileAsync(string filename, byte[] key, byte[] nonce, string? outputFilePath = null, CancellationToken ct = default)
    {
        ValidateParameters(filename, key, nonce);

        outputFilePath ??= filename;

        byte[] plaintext = await _fileSystem.File.ReadAllBytesAsync(filename, ct).ConfigureAwait(false);
        byte[] encryptedData = AesGcmUtils.Encrypt(plaintext, key, nonce);
        await _fileSystem.File.WriteAllBytesAsync(outputFilePath, encryptedData, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Asynchronously decrypts a file using AES-GCM, ensuring data authenticity.
    /// </summary>
    /// <param name="filename">The name of the file to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="nonce">The nonce used for encryption.</param>
    /// <param name="outputFilePath">The output file path. If null, the original file is overwritten.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task DecryptFileAsync(string filename, byte[] key, byte[] nonce, string? outputFilePath = null, CancellationToken ct = default)
    {
        ValidateParameters(filename, key, nonce);
        if (!_fileSystem.File.Exists(filename))
        {
            throw new FileNotFoundException("File to be decrypted not found.", filename);
        }

        outputFilePath ??= filename;

        byte[] encryptedData = await _fileSystem.File.ReadAllBytesAsync(filename, ct).ConfigureAwait(false);
        byte[] decryptedData = AesGcmUtils.Decrypt(encryptedData, key, nonce);
        await _fileSystem.File.WriteAllBytesAsync(outputFilePath, decryptedData, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Synchronously encrypts a file using AES-GCM, providing authenticated encryption.
    /// </summary>
    /// <param name="filename">The name of the file to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="nonce">The nonce used for encryption.</param>
    /// <param name="outputFilePath">The output file path. If null, the original file is overwritten.</param>
    public void EncryptFile(string filename, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, string? outputFilePath = null)
    {
        ValidateParameters(filename, key, nonce);

        outputFilePath ??= filename;

        ReadOnlySpan<byte> plaintext = _fileSystem.File.ReadAllBytes(filename);
        byte[] encryptedData = AesGcmUtils.Encrypt(plaintext, key, nonce);
        _fileSystem.File.WriteAllBytes(outputFilePath, encryptedData);
    }

    /// <summary>
    /// Synchronously decrypts a file using AES-GCM, ensuring data authenticity.
    /// </summary>
    /// <param name="filename">The name of the file to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="nonce">The nonce used for encryption.</param>
    /// <param name="outputFilePath">The output file path. If null, the original file is overwritten.</param>
    public void DecryptFile(string filename, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, string? outputFilePath = null)
    {
        ValidateParameters(filename, key, nonce);
        if (!_fileSystem.File.Exists(filename))
        {
            throw new FileNotFoundException("File to be decrypted not found.", filename);
        }

        outputFilePath ??= filename;

        ReadOnlySpan<byte> encryptedData = _fileSystem.File.ReadAllBytes(filename);
        byte[] decryptedData = AesGcmUtils.Decrypt(encryptedData, key, nonce);
        _fileSystem.File.WriteAllBytes(outputFilePath, decryptedData);
    }

    private static void ValidateParameters(string filename, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (string.IsNullOrWhiteSpace(filename))
        {
            throw new ArgumentException("Filename must not be null or empty.", nameof(filename));
        }

        if (key.IsEmpty || key.Length != 32)
        {
            throw new ArgumentException("Invalid key length. Key must be 32 bytes.", nameof(key));
        }

        if (nonce.IsEmpty || nonce.Length != AesGcm.NonceByteSizes.MaxSize)
        {
            throw new ArgumentException("Invalid nonce length. Nonce must be 12 bytes.", nameof(nonce));
        }
    }
}