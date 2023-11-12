using Seif.Rng;
using Seif.Rng.Sandbox.Benchmarks;

#pragma warning disable S1075
#pragma warning disable S125

// Generate encryption key (32 bytes for AES-256)


// using FileCryptoService = Seif.Rng.FileCryptoService;
//
// byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
// // Generate a nonce (12 bytes is a common length for GCM)
// var nonce = new byte[12];
// using var randomNumberGenerator = RandomNumberGenerator.Create();
// randomNumberGenerator.GetBytes(nonce);
//
//
// const string testFilePath = @"E:\temp\testfile.txt";
// const string testFileOutPath = @"E:\temp\testfile_enc.txt";
//
// FileCryptoService.EncryptFile(testFilePath, testFileOutPath, key, nonce);
//
// FileCryptoService.DecryptFile(testFileOutPath, @"E:\temp\testfile_dec.txt", key, nonce);

// var sampleData = new byte[81_920]; // Example size
// var key = new byte[32]; // Key should be 32 bytes for AES-256
// var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // Typically 12 bytes for AES-GCM
//
// using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
// rng.GetBytes(sampleData);
// rng.GetBytes(key);
// rng.GetBytes(nonce);
//
// // Pre-encrypt data for decrypt benchmarks
// AesGcmUtils.Encrypt(sampleData, key, nonce);

BenchmarkRunner.Run<AesGcmBenchmark>();