using AI.Sentinel.Authorization;

namespace AI.Sentinel.Approvals;

/// <summary>
/// Formats the human-readable "deny-with-receipt" message that stateless CLI hosts
/// (Claude Code hooks, Copilot hooks, fail-fast MCP proxy) surface when an authorization
/// check returns <see cref="AuthorizationDecision.RequireApprovalDecision"/>. The text
/// tells the operator how to find the pending request and what URL to approve at, so
/// they can grant the approval out of band and retry the call.
/// </summary>
public static class ApprovalReceipt
{
    /// <summary>Formats a deny-with-receipt message for stateless CLI hosts.</summary>
    public static string Format(string toolName, AuthorizationDecision.RequireApprovalDecision r)
    {
        ArgumentException.ThrowIfNullOrEmpty(toolName);
        ArgumentNullException.ThrowIfNull(r);
        return
            $"Approval required to invoke tool '{toolName}'.\n" +
            $"Request ID: {r.RequestId}\n" +
            $"Approve at: {r.ApprovalUrl}\n" +
            "Once approved, retry the tool call.";
    }
}
