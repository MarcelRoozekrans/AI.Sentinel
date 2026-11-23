namespace AI.Sentinel.Profiles;

/// <summary>The outcome of <see cref="ProfileVerifier.Verify"/>: the accepted profile, or the reason it was refused.</summary>
internal sealed class ProfileVerification
{
    private ProfileVerification(PolicyProfile? profile, ProfileRejection rejection, byte[]? endorsedKey)
    {
        Profile = profile;
        Rejection = rejection;
        EndorsedKey = endorsedKey;
    }

    /// <summary>
    /// The public key that signed, when it was not pinned and a pinned key endorsed it. The caller adds it with
    /// <see cref="PinnedProfileKeys.With"/>, so later profiles verify without the endorsement.
    /// </summary>
    public byte[]? EndorsedKey { get; }

    /// <summary>The profile, only when it was accepted.</summary>
    public PolicyProfile? Profile { get; }

    /// <summary><see cref="ProfileRejection.None"/> when accepted.</summary>
    public ProfileRejection Rejection { get; }

    /// <summary>True when the profile may be enforced.</summary>
    public bool IsAccepted => Rejection == ProfileRejection.None;

    internal static ProfileVerification Accepted(PolicyProfile profile, byte[]? endorsedKey = null) =>
        new(profile, ProfileRejection.None, endorsedKey);

    internal static ProfileVerification Rejected(ProfileRejection reason) => new(null, reason, null);
}
