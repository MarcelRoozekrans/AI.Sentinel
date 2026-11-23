using System.Security.Cryptography;

namespace AI.Sentinel.Profiles;

/// <summary>The id of a profile key: the first 16 bytes of the SHA-256 of its public key, as lowercase hex.</summary>
internal static class ProfileKeyId
{
    public static string Of(ReadOnlySpan<byte> publicKey) =>
        Convert.ToHexStringLower(SHA256.HashData(publicKey).AsSpan(0, 16));
}
