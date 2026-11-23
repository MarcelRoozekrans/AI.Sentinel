using System.Text.Json;
using System.Text.Json.Serialization;

namespace AI.Sentinel.Profiles;

/// <summary>
/// A profile with its signature, as the server sends it and the plugin caches it. The profile travels as base64 of
/// its canonical bytes, so verification checks the exact bytes that were signed and never re-serialises them.
/// </summary>
internal sealed record SignedProfile
{
    /// <summary>Base64 of the canonical JSON bytes of the <see cref="PolicyProfile"/>.</summary>
    [JsonPropertyName("profile")]
    public required string Profile { get; init; }

    /// <summary>The id of the key that signed, see <see cref="ProfileKeyId"/>.</summary>
    [JsonPropertyName("key_id")]
    public required string KeyId { get; init; }

    /// <summary>Base64 of the 64 byte Ed25519 signature over the canonical bytes.</summary>
    [JsonPropertyName("signature")]
    public required string Signature { get; init; }

    /// <summary>
    /// Endorsements of the signing key by older keys, present during a key rotation. Plugins that pinned only an old key
    /// accept the signing key through one of them.
    /// </summary>
    [JsonPropertyName("endorsements")]
    public IReadOnlyList<KeyEndorsement> Endorsements { get; init; } = [];

    /// <summary>The envelope as JSON.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, ProfileJsonContext.Default.SignedProfile);

    /// <summary>Reads an envelope; null when the text is not one.</summary>
    public static SignedProfile? Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            var parsed = JsonSerializer.Deserialize(json, ProfileJsonContext.Default.SignedProfile);
            if (parsed is null)
            {
                return null;
            }
            // For a type with required members the generated reader leaves an absent member at null, not at its
            // initializer, and lets an explicit null through: both mean no endorsements. A null entry is refused.
            if (parsed.Endorsements is null)
            {
                return parsed with { Endorsements = [] };
            }
            return parsed.Endorsements.Any(e => e is null) ? null : parsed;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
