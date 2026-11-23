namespace AI.Sentinel.Profiles;

/// <summary>
/// An Ed25519 key the server signs profiles with. It lives in memory only: it is handed in by the deployment at
/// startup, there is no way to read it back out, save it or fetch it later (ADR-230).
/// </summary>
internal sealed class ProfileSigningKey
{
    private readonly byte[] _seed;

    /// <summary>Takes the 32 byte seed of the key. The array is copied.</summary>
    public ProfileSigningKey(ReadOnlySpan<byte> seed)
    {
        _seed = seed.ToArray();
        PublicKey = Ed25519Crypto.PublicKey(_seed);
        KeyId = ProfileKeyId.Of(PublicKey);
    }

    /// <summary>Takes the seed as base64, the form a deployment passes it in.</summary>
    /// <exception cref="FormatException">The text is not base64 of 32 bytes.</exception>
    public static ProfileSigningKey FromBase64(string seed)
    {
        ArgumentException.ThrowIfNullOrEmpty(seed);
        try
        {
            return new ProfileSigningKey(Convert.FromBase64String(seed));
        }
        catch (ArgumentException ex)
        {
            throw new FormatException("A profile signing key is the base64 of a 32 byte Ed25519 seed.", ex);
        }
    }

    /// <summary>Makes a new random key. For tests and tooling that creates keys for a deployment.</summary>
    public static ProfileSigningKey Generate() => new(Ed25519Crypto.NewSeed());

    /// <summary>The id of the public key.</summary>
    public string KeyId { get; }

    /// <summary>The public half. A copy is safe to give to plugins to pin.</summary>
    public byte[] PublicKey { get; }

    internal byte[] Sign(ReadOnlySpan<byte> message) => Ed25519Crypto.Sign(_seed, message);

    /// <summary>Never prints key material.</summary>
    public override string ToString() => $"ProfileSigningKey {KeyId}";
}
