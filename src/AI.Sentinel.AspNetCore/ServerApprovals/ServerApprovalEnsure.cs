namespace AI.Sentinel.AspNetCore.ServerApprovals;

/// <summary>What <see cref="ServerApprovalStore.Ensure"/> found or made.</summary>
internal readonly record struct ServerApprovalEnsure(ServerApproval Approval, bool IsNew);
