namespace AI.Sentinel.Profiles;

/// <summary>Values of <see cref="PolicyProfile.FailMode"/>.</summary>
internal static class ProfileFailModes
{
    /// <summary>An internal error blocks the call.</summary>
    public const string Closed = "closed";

    /// <summary>An internal error lets the call through.</summary>
    public const string Open = "open";

    internal static bool IsValid(string? value) =>
        string.Equals(value, Closed, StringComparison.Ordinal) || string.Equals(value, Open, StringComparison.Ordinal);
}
