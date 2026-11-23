namespace AI.Sentinel.Profiles;

/// <summary>
/// The signing keys the deployment gives the server at startup: the key that signs, and during a rotation the old key
/// next to it. The server never fetches a key at runtime and never stores one (ADR-230); a restart with the
/// deployment's new setting is how a key changes.
/// </summary>
/// <remarks>
/// Rotation: the deployment sets <see cref="Current"/> to the new key and <see cref="Previous"/> to the old one.
/// Every profile is signed by the new key and carries an endorsement of it by the old key, so plugins that pinned only
/// the old key accept it and pin the new one. Once every plugin has seen a profile, the deployment drops the old key.
/// </remarks>
internal sealed class ProfileSigningKeys
{
    /// <summary>Keys with no rotation under way.</summary>
    public ProfileSigningKeys(ProfileSigningKey current, ProfileSigningKey? previous = null)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (previous is not null && string.Equals(previous.KeyId, current.KeyId, StringComparison.Ordinal))
        {
            throw new ArgumentException("The previous key is the same key as the current one.", nameof(previous));
        }
        Current = current;
        Previous = previous;
    }

    /// <summary>Reads the keys as the deployment passes them: base64 seeds. Leave <paramref name="previous"/> empty outside a rotation.</summary>
    /// <exception cref="FormatException">A seed is not base64 of 32 bytes.</exception>
    public static ProfileSigningKeys FromBase64(string current, string? previous = null) =>
        new(ProfileSigningKey.FromBase64(current), string.IsNullOrWhiteSpace(previous) ? null : ProfileSigningKey.FromBase64(previous));

    /// <summary>The key that signs every profile.</summary>
    public ProfileSigningKey Current { get; }

    /// <summary>The old key, present only during a rotation. It endorses <see cref="Current"/>.</summary>
    public ProfileSigningKey? Previous { get; }
}
