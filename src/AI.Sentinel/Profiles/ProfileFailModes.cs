namespace AI.Sentinel.Profiles;

/// <summary>Values of <see cref="PolicyProfile.FailMode"/>: what a hook does with a call that no policy decision can be made for
/// (ADR-237). There is no value that lets such a call through.</summary>
internal static class ProfileFailModes
{
    /// <summary>The call is denied, with guidance. The default.</summary>
    public const string Closed = "closed";

    /// <summary>The developer is asked, where the CLI can ask; where it cannot, the call is denied.</summary>
    public const string Ask = "ask";

    internal static bool IsValid(string? value) =>
        string.Equals(value, Closed, StringComparison.Ordinal) || string.Equals(value, Ask, StringComparison.Ordinal);
}
