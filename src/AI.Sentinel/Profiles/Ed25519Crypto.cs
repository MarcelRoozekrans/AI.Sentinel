using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace AI.Sentinel.Profiles;

/// <summary>
/// Ed25519 (RFC 8032, pure) on the managed BouncyCastle implementation: the .NET BCL has no Ed25519, and a managed
/// library needs no native binary per operating system, which keeps the hook tools Native AOT on Windows, Linux
/// and macOS. A key pair is a 32 byte seed and a 32 byte public key; a signature is 64 bytes.
/// </summary>
internal static class Ed25519Crypto
{
    public const int SeedSize = 32;
    public const int PublicKeySize = 32;
    public const int SignatureSize = 64;

    /// <summary>A new random seed.</summary>
    public static byte[] NewSeed() => RandomNumberGenerator.GetBytes(SeedSize);

    /// <summary>The public key of <paramref name="seed"/>.</summary>
    public static byte[] PublicKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedSize)
        {
            throw new ArgumentException($"An Ed25519 seed is {SeedSize} bytes.", nameof(seed));
        }
        var publicKey = new byte[PublicKeySize];
        Ed25519.GeneratePublicKey(seed.ToArray(), 0, publicKey, 0);
        return publicKey;
    }

    /// <summary>Signs <paramref name="message"/> with the key of <paramref name="seed"/>.</summary>
    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        if (seed.Length != SeedSize)
        {
            throw new ArgumentException($"An Ed25519 seed is {SeedSize} bytes.", nameof(seed));
        }
        var signature = new byte[SignatureSize];
        var m = message.ToArray();
        Ed25519.Sign(seed.ToArray(), 0, m, 0, m.Length, signature, 0);
        return signature;
    }

    /// <summary>True when <paramref name="signature"/> is a valid signature of <paramref name="message"/> by <paramref name="publicKey"/>.</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize || signature.Length != SignatureSize)
        {
            return false;
        }
        var m = message.ToArray();
        return Ed25519.Verify(signature.ToArray(), 0, publicKey.ToArray(), 0, m, 0, m.Length);
    }
}
