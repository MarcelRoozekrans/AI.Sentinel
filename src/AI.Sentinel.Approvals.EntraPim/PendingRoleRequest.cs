namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>An activation request already open in PIM for a (principal, role) pair.</summary>
internal sealed record PendingRoleRequest(string RequestId, DateTimeOffset CreatedAt);
