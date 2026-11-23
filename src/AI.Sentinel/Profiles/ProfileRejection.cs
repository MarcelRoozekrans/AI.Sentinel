namespace AI.Sentinel.Profiles;

/// <summary>Why <see cref="ProfileVerifier"/> refused a profile. Every reason is its own value.</summary>
internal enum ProfileRejection
{
    /// <summary>The profile was accepted.</summary>
    None = 0,

    /// <summary>The envelope or the profile in it cannot be read, or the profile is not in canonical form.</summary>
    Malformed,

    /// <summary>The signing key is not pinned and no pinned key endorses it.</summary>
    UnknownKey,

    /// <summary>The signature does not match the profile bytes: a changed byte or another key.</summary>
    BadSignature,

    /// <summary>The profile's expiry has passed.</summary>
    Expired,

    /// <summary>The profile was issued for another organisation than the one signed in to.</summary>
    OrganisationMismatch,

    /// <summary>The profile was issued for another repository than the one asked for.</summary>
    RepositoryMismatch,
}
