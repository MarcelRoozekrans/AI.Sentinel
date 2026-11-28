using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>
/// What a hook knows about its profile when it has to say what a call that no decision can be made for gets (#673). Both hook CLIs
/// build it with <see cref="Repository.HookProfiles.Open"/> from the profiles cached with the keys pinned at sign-in (#729), and pass it
/// to <see cref="LocalPolicy.Load"/> and <see cref="FailModeGate"/>. Without a server configured there is none, and nothing changes.
/// </summary>
/// <param name="ServerConfigured">A server is configured, so a profile is expected. Without one there is no profile to miss.</param>
/// <param name="ProfileUsable">A valid, unexpired profile is cached, so the policy decides and the fail mode only covers an evaluation
/// that gave no answer.</param>
/// <param name="FailMode">The <c>fail_mode</c> to apply, one of <see cref="ProfileFailModes"/>; <see langword="null"/> when there is no
/// profile to read it from, which is closed.</param>
/// <param name="Cause">Why no decision can be made, for the developer.</param>
/// <param name="NeedsSignIn">Nothing is cached, so what helps is signing in.</param>
internal sealed record FailModeContext(bool ServerConfigured, bool ProfileUsable, string? FailMode, string Cause, bool NeedsSignIn = false)
{
    /// <summary>No server is configured: there is no profile to miss and nothing here applies to a missing one.</summary>
    public static FailModeContext NoServer { get; } = new(false, false, null, string.Empty);

    /// <summary>A server is configured and nothing is cached, which includes a developer who has not signed in yet.</summary>
    public static FailModeContext NotSignedIn { get; } =
        new(true, false, null, "you are not signed in to the AI.Sentinel server, so there is no policy profile for this repository", NeedsSignIn: true);

    /// <summary>The developer signed in, and the profile the call needs is not cached yet: the resident process has not fetched it.</summary>
    public static FailModeContext NoProfile { get; } =
        new(true, false, null, "no policy profile for this repository is cached yet");

    /// <summary>The developer signed in, and the map of which node owns which repository is not cached yet, so the profile that applies
    /// is not known.</summary>
    public static FailModeContext NoNodeMap { get; } =
        new(true, false, null, "the map of which node owns which repository is not cached yet, so the policy profile that applies is not known");

    /// <summary>True when the developer is asked instead of the call being denied.</summary>
    public bool Asks => string.Equals(FailMode, ProfileFailModes.Ask, StringComparison.Ordinal);

    /// <summary>The context for the cached profile of a hook that has a server configured, as <c>ResidentState.ReadProfile</c> returned
    /// it; <see langword="null"/> for none.</summary>
    public static FailModeContext From(ProfileVerification? cached)
    {
        if (cached is null)
        {
            return NotSignedIn;
        }

        if (cached.IsAccepted)
        {
            return new FailModeContext(true, true, cached.Profile!.FailMode, "the policy could not be evaluated");
        }

        return cached.Rejection == ProfileRejection.Expired
            ? new FailModeContext(true, false, cached.FailMode, "the cached policy profile has expired and could not be refreshed")
            : new FailModeContext(true, false, null, $"the cached policy profile cannot be used ({cached.Rejection})");
    }
}
