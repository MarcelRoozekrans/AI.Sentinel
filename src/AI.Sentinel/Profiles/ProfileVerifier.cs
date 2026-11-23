namespace AI.Sentinel.Profiles;

/// <summary>
/// The plugin side: accepts a <see cref="SignedProfile"/> only when a pinned key signed it, its bytes are intact and
/// canonical, it has not expired, and it was issued for the organisation signed in to and the repository asked for.
/// Cached profiles go through the same check, so a cache that fails it is unusable and one that passes is usable
/// offline until it expires.
/// </summary>
internal static class ProfileVerifier
{
    /// <summary>Checks <paramref name="signed"/> and returns the profile or the reason it was refused.</summary>
    /// <param name="signed">The envelope from the server or the cache.</param>
    /// <param name="pinned">The keys pinned at sign-in.</param>
    /// <param name="organisation">The organisation signed in to.</param>
    /// <param name="repository">The repository the profile was asked for.</param>
    /// <param name="now">The current time.</param>
    public static ProfileVerification Verify(
        SignedProfile signed,
        PinnedProfileKeys pinned,
        string organisation,
        string repository,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(signed);
        ArgumentNullException.ThrowIfNull(pinned);
        ArgumentNullException.ThrowIfNull(organisation);
        ArgumentNullException.ThrowIfNull(repository);

        if (!TryFromBase64(signed.Profile, out var bytes) || !TryFromBase64(signed.Signature, out var signature))
        {
            return ProfileVerification.Rejected(ProfileRejection.Malformed);
        }
        if (!pinned.TryGet(signed.KeyId, out var publicKey))
        {
            return ProfileVerification.Rejected(ProfileRejection.UnknownKey);
        }
        if (!Ed25519Crypto.Verify(publicKey, bytes, signature))
        {
            return ProfileVerification.Rejected(ProfileRejection.BadSignature);
        }

        var profile = ProfileCanonicalJson.Deserialize(bytes);
        if (profile is null || !ProfileCanonicalJson.IsCanonical(bytes, profile))
        {
            return ProfileVerification.Rejected(ProfileRejection.Malformed);
        }
        if (!string.Equals(profile.Organisation, organisation, StringComparison.Ordinal))
        {
            return ProfileVerification.Rejected(ProfileRejection.OrganisationMismatch);
        }
        if (!string.Equals(profile.Repository, repository, StringComparison.Ordinal))
        {
            return ProfileVerification.Rejected(ProfileRejection.RepositoryMismatch);
        }
        if (now >= profile.ExpiresAt)
        {
            return ProfileVerification.Rejected(ProfileRejection.Expired);
        }
        return ProfileVerification.Accepted(profile);
    }

    private static bool TryFromBase64(string text, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(text);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
