namespace AI.Sentinel.Authorization;

/// <summary>Result of a tool-call authorization check. Closed hierarchy — see nested records.</summary>
public abstract record AuthorizationDecision
{
    /// <summary>Decision permitting the call.</summary>
    public sealed record AllowDecision : AuthorizationDecision;

    /// <summary>Decision refusing the call, naming the policy and reason.</summary>
    /// <param name="PolicyName">Name of the denying policy.</param>
    /// <param name="Reason">Human-readable reason for the denial.</param>
    public sealed record DenyDecision(string PolicyName, string Reason) : AuthorizationDecision;

    /// <summary>Singleton allow — never allocates.</summary>
    public static readonly AllowDecision Allow = new();

    /// <summary>Builds a deny decision with the policy name and reason that produced it.</summary>
    /// <param name="policyName">Name of the denying policy.</param>
    /// <param name="reason">Human-readable reason for the denial.</param>
    public static DenyDecision Deny(string policyName, string reason) =>
        new(policyName, reason);

    /// <summary>True if this decision permits the call.</summary>
    public bool Allowed => this is AllowDecision;
}
