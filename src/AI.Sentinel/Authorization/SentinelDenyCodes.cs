namespace AI.Sentinel.Authorization;

/// <summary>The well-known deny codes AI.Sentinel emits via <see cref="AuthorizationDecision.DenyDecision"/>'s
/// <c>Code</c> field, <see cref="Audit.AuditEntry"/>'s <c>PolicyCode</c> property, and downstream surfaces
/// (audit forwarders, hook receipts, MCP error message, dashboard badge). Third-party policies emit
/// their own codes — the structured-failure surface accepts any string. These constants document the
/// canonical set AI.Sentinel itself produces.</summary>
public static class SentinelDenyCodes
{
    /// <summary>Policy returned <c>IsAuthorized=false</c> (sync) or an unstructured failure. Default
    /// code on the bare-deny path; also the <c>SqliteAuditStore</c> column DEFAULT for legacy rows.</summary>
    public const string PolicyDenied = "policy_denied";

    /// <summary>A binding referenced a policy name that was never registered with the DI container.
    /// Failure-closed (deny) — recovery is operator action.</summary>
    public const string PolicyNotRegistered = "policy_not_registered";

    /// <summary>The policy threw a non-cancellation exception during evaluation. Failure-closed.</summary>
    public const string PolicyException = "policy_exception";

    /// <summary>Audit-entry tag for a tool call that was held up in the require-approval flow.
    /// Distinguishes pending approvals from real policy denials in audit queries.</summary>
    public const string ApprovalRequired = "approval_required";

    /// <summary>The approval store threw during request creation or status query. Failure-closed.</summary>
    public const string ApprovalStoreException = "approval_store_exception";

    /// <summary>An <c>ApprovalState</c> subclass not covered by the guard's switch arms (defensive
    /// fallback). Should not occur in practice — flagged distinctly for diagnostic purposes.</summary>
    public const string ApprovalStateUnknown = "approval_state_unknown";
}
