namespace AI.Sentinel.Authorization;

/// <summary>The well-known deny codes AI.Sentinel emits via <see cref="AuthorizationDecision.DenyDecision"/>'s
/// <c>Code</c> field, <see cref="Audit.AuditEntry"/>'s <c>PolicyCode</c> property, and downstream surfaces
/// (audit forwarders, hook receipts, MCP error message, dashboard badge). Third-party policies emit
/// their own codes — the structured-failure surface accepts any string. These constants document the
/// canonical set AI.Sentinel itself produces.
/// <para>
/// Two implicit categories:
/// <list type="bullet">
/// <item><description><b>Fail-closed</b> — policy refused or could not be evaluated:
/// <see cref="PolicyDenied"/>, <see cref="PolicyNotRegistered"/>, <see cref="PolicyException"/>,
/// <see cref="ApprovalStoreException"/>, <see cref="ApprovalStateUnknown"/></description></item>
/// <item><description><b>Approval-flow</b> — tool call deferred to out-of-band approval:
/// <see cref="ApprovalRequired"/></description></item>
/// </list>
/// </para>
/// <para>
/// To add a 7th code: (1) add a <c>public const string</c> field below with an XML doc explaining when
/// it's emitted and which category it belongs to; (2) extend
/// <c>SentinelDenyCodesTests.Constants_MatchWireFormat</c> with the new wire-format assertion;
/// (3) reference the constant at the emit site (don't hardcode the string elsewhere in <c>src/</c>,
/// except in <c>SqliteSchema.cs</c> SQL DEFAULT clauses and XML doc comments where the literal aids
/// human readability).
/// </para></summary>
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
