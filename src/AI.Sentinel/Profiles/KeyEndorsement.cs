using System.Text;
using System.Text.Json.Serialization;

namespace AI.Sentinel.Profiles;

/// <summary>
/// A statement that a pinned key vouches for a new key, so plugins that pinned only the old key accept profiles signed
/// by the new one (key rotation). The signature is over a fixed text prefix and the new public key, so it can never be
/// mistaken for a profile signature: a canonical profile starts with an opening brace and this does not.
/// </summary>
internal sealed record KeyEndorsement
{
    private static readonly byte[] Prefix = Encoding.UTF8.GetBytes("ai-sentinel/profile-key-endorsement/v1\n");

    /// <summary>The id of the endorsed key.</summary>
    [JsonPropertyName("key_id")]
    public required string KeyId { get; init; }

    /// <summary>Base64 of the endorsed 32 byte public key.</summary>
    [JsonPropertyName("public_key")]
    public required string PublicKey { get; init; }

    /// <summary>The id of the key that endorses; it must be pinned by the plugin.</summary>
    [JsonPropertyName("endorsed_by")]
    public required string EndorsedBy { get; init; }

    /// <summary>Base64 of the Ed25519 signature by the endorsing key.</summary>
    [JsonPropertyName("signature")]
    public required string Signature { get; init; }

    /// <summary>Makes the endorsement of <paramref name="endorsed"/> by <paramref name="endorser"/>.</summary>
    internal static KeyEndorsement Create(ProfileSigningKey endorser, ProfileSigningKey endorsed) => new()
    {
        KeyId = endorsed.KeyId,
        PublicKey = Convert.ToBase64String(endorsed.PublicKey),
        EndorsedBy = endorser.KeyId,
        Signature = Convert.ToBase64String(endorser.Sign(Message(endorsed.PublicKey))),
    };

    /// <summary>
    /// The endorsed public key when this endorsement names <paramref name="keyId"/>, is by a key in
    /// <paramref name="pinned"/> and carries a valid signature; otherwise null.
    /// </summary>
    internal byte[]? TryAccept(string keyId, PinnedProfileKeys pinned)
    {
        if (!string.Equals(KeyId, keyId, StringComparison.Ordinal) || !pinned.TryGet(EndorsedBy, out var endorserKey))
        {
            return null;
        }
        try
        {
            var publicKey = Convert.FromBase64String(PublicKey);
            var signature = Convert.FromBase64String(Signature);
            return publicKey.Length == Ed25519Crypto.PublicKeySize
                && string.Equals(ProfileKeyId.Of(publicKey), keyId, StringComparison.Ordinal)
                && Ed25519Crypto.Verify(endorserKey, Message(publicKey), signature)
                ? publicKey
                : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static byte[] Message(byte[] publicKey) => [.. Prefix, .. publicKey];
}
