namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>A place ran the policy bundle and the bundle failed while it ran (#716). That is an evaluation, and ADR-237 denies it by
/// bundle name, so no later place is asked for another answer. The message never carries what the bundle raised: a module that aborts
/// may echo what it was given, and that is the tool input.</summary>
internal sealed class PolicyBundleException : Exception
{
    public PolicyBundleException(string message)
        : base(message)
    {
    }

    public PolicyBundleException()
    {
    }

    public PolicyBundleException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The failure the resident process reported, by the type of the error it saw.</summary>
    internal static PolicyBundleException FromResident(string? errorType) =>
        new($"the policy bundle failed while it ran in the resident process ({errorType ?? "unknown error"})");
}
