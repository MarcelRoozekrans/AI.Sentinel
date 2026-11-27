using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The states an approval request has on the wire (#662).</summary>
internal static class ApprovalWireStates
{
    public const string Pending = "pending";
    public const string Active = "active";
    public const string Denied = "denied";
}
