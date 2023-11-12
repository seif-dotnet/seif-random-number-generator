#pragma warning disable SCS0005, CA5394 // Disable warning for weak random number generator

namespace Seif.Rng.Tests.TestData;

internal static class EncryptionTestData
{
    public const string ShortTextData = "Hello, World!";

    // Create 10KB of random characters
    public static readonly string LongTextData = new(Enumerable.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 10000)
        .Select(s =>
        {
            int i = new Random().Next(s.Length);
            if (i >= 0 && i < s.Length) return s[i];
            return '\0';
        }).ToArray());

    public static readonly byte[] ShortByteData = RandomNumberGenerator.GetBytes(100); // 100 bytes
    public static readonly byte[] LongByteData = RandomNumberGenerator.GetBytes(10000); // 10KB
}