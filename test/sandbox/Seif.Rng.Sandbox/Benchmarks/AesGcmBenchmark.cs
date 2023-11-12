namespace Seif.Rng.Sandbox.Benchmarks;

[MemoryDiagnoser]
public class AesGcmBenchmark
{
    private readonly byte[] _sampleData;
    private readonly byte[] _key;
    private readonly byte[] _nonce;
    private readonly byte[] _encryptedDataOptimized;
    private readonly byte[] _encryptedDataUnoptimized;

    public AesGcmBenchmark()
    {
        _sampleData = new byte[81_920]; // Example size
        _key = new byte[32]; // Key should be 32 bytes for AES-256
        _nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // Typically 12 bytes for AES-GCM

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(_sampleData);
        rng.GetBytes(_key);
        rng.GetBytes(_nonce);

        // Pre-encrypt data for decrypt benchmarks
        _encryptedDataOptimized = AesGcmUtils.Encrypt(_sampleData, _key, _nonce);
        _encryptedDataUnoptimized = AesGcmUtilsUnOptimized.Encrypt(_sampleData, _key, _nonce);
    }

    [Benchmark]
    public void EncryptOptimized()
    {
        AesGcmUtils.Encrypt(_sampleData, _key, _nonce);
    }

    [Benchmark]
    public void EncryptUnoptimized()
    {
        AesGcmUtilsUnOptimized.Encrypt(_sampleData, _key, _nonce);
    }

    [Benchmark]
    public void DecryptOptimized()
    {
        AesGcmUtils.Decrypt(_encryptedDataOptimized, _key, _nonce);
    }

    [Benchmark]
    public void DecryptUnoptimized()
    {
        AesGcmUtilsUnOptimized.Decrypt(_encryptedDataUnoptimized, _key, _nonce);
    }

    // [Benchmark]
    // public void EncryptDecryptCombinedOptimized()
#pragma warning disable S125
    // {
#pragma warning restore S125
    //     byte[] encrypted = AesGcmUtils.Encrypt(_sampleData, _key, _nonce);
    //     AesGcmUtils.Decrypt(encrypted, _key, _nonce);
    // }
    //
    // [Benchmark]
    // public void EncryptDecryptCombinedUnoptimized()
    // {
    //     byte[] encrypted = AesGcmUtilsUnOptimized.Encrypt(_sampleData, _key, _nonce);
    //     AesGcmUtilsUnOptimized.Decrypt(encrypted, _key, _nonce);
    // }
}