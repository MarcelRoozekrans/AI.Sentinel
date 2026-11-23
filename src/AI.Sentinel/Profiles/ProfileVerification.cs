namespace AI.Sentinel.Profiles;

/// <summary>The outcome of <see cref="ProfileVerifier.Verify"/>: the accepted profile, or the reason it was refused.</summary>
internal sealed class ProfileVerification
{
    private ProfileVerification(PolicyProfile? profile, ProfileRejection rejection)
    {
        Profile = profile;
        Rejection = rejection;
    }

    /// <summary>The profile, only when it was accepted.</summary>
    public PolicyProfile? Profile { get; }

    /// <summary><see cref="ProfileRejection.None"/> when accepted.</summary>
    public ProfileRejection Rejection { get; }

    /// <summary>True when the profile may be enforced.</summary>
    public bool IsAccepted => Rejection == ProfileRejection.None;

    internal static ProfileVerification Accepted(PolicyProfile profile) => new(profile, ProfileRejection.None);

    internal static ProfileVerification Rejected(ProfileRejection reason) => new(null, reason);
}
