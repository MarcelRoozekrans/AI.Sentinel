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

    public sealed record RequireApprovalDecision(
        string PolicyName,
        string RequestId,
        string ApprovalUrl,
        DateTimeOffset RequestedAt,
        TimeSpan WaitTimeout) : AuthorizationDecision;

    public static RequireApprovalDecision RequireApproval(
        string policyName, string requestId, string approvalUrl,
        DateTimeOffset requestedAt, TimeSpan waitTimeout) =>
        new(policyName, requestId, approvalUrl, requestedAt, waitTimeout);

    /// <summary>
    /// Folds a <see cref="RequireApprovalDecision"/> into a <see cref="DenyDecision"/> for callers
    /// that don't participate in the approval flow (CS8509 dodge).
    /// </summary>
    public AuthorizationDecision AsBinary() =>
        this is RequireApprovalDecision r
            ? Deny(r.PolicyName, $"approval required (requestId={r.RequestId})")
            : this;

    /// <summary>True if this decision permits the call.</summary>
    public bool Allowed => this is AllowDecision;
}
