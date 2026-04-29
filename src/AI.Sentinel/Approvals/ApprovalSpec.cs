namespace AI.Sentinel.Approvals;

/// <summary>
/// Configuration for an approval-required tool binding. Read by <see cref="IApprovalStore"/>
/// implementations to decide grant duration, justification policy, and backend-specific
/// bindings (e.g., PIM role name).
/// </summary>
public sealed class ApprovalSpec
{
    /// <summary>The policy name the approval gate is bound to. Used as the dedupe key
    /// alongside the caller identity.</summary>
    public required string PolicyName { get; init; }

    /// <summary>How long an approved grant remains active before re-approval is needed.</summary>
    public TimeSpan GrantDuration { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Whether a justification string must be provided at request time.</summary>
    public bool RequireJustification { get; init; } = true;

    /// <summary>Maximum time a host that block-and-waits will tolerate before timing out.</summary>
    public TimeSpan WaitTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Backend-specific identifier (PIM role name for EntraPim, ignored otherwise).</summary>
    public string? BackendBinding { get; init; }
}
