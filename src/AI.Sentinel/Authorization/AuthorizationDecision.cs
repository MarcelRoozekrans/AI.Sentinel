namespace AI.Sentinel.Authorization;

/// <summary>Result of a tool-call authorization check.</summary>
/// <param name="Allowed">Whether the call is permitted.</param>
/// <param name="PolicyName">Name of the policy that produced the decision, when applicable.</param>
/// <param name="Reason">Human-readable explanation for the decision, when applicable.</param>
public sealed record AuthorizationDecision(bool Allowed, string? PolicyName, string? Reason)
{
    /// <summary>Singleton for the allow path — never allocates.</summary>
    public static readonly AuthorizationDecision Allow = new(true, null, null);

    /// <summary>Builds a deny decision with the policy name and reason that produced it.</summary>
    /// <param name="policyName">Name of the denying policy.</param>
    /// <param name="reason">Human-readable reason for the denial.</param>
    public static AuthorizationDecision Deny(string policyName, string reason) =>
        new(false, policyName, reason);
}
