using System.Collections.Concurrent;

namespace AI.Sentinel.Approvals;

/// <summary>What this process has seen of one inner store's requests. Thread-safe.</summary>
internal sealed class ApprovalAuditMemory
{
    /// <summary>Policy and tool of each open request, by request id.</summary>
    public ConcurrentDictionary<string, RequestInfo> Requests { get; } = new(StringComparer.Ordinal);

    /// <summary>The latest request id of each caller and policy, the key the stores dedupe on.</summary>
    public ConcurrentDictionary<string, string> RequestIdByCallerPolicy { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Request ids whose outcome this process has recorded. For a store without <see cref="IApprovalAdmin"/> this is
    /// the memory of the first Active or Denied observed, dropped when the grant expires, a denial names the request
    /// or the caller opens a new request for the same policy; for an admin store it keeps two racing calls from both
    /// recording, and an id is dropped once the store reports the request settled and forgets it.
    /// </summary>
    public ConcurrentDictionary<string, byte> Settled { get; } = new(StringComparer.Ordinal);

    /// <summary>The policy and tool of an approval request, as seen when it was opened.</summary>
    public readonly record struct RequestInfo(string PolicyName, string ToolName);

    /// <summary>The key of <see cref="RequestIdByCallerPolicy"/>.</summary>
    public static string CallerPolicyKey(string callerId, string policyName) => callerId + "\n" + policyName;
}
