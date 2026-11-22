namespace AI.Sentinel.Approvals;

/// <summary>What an <see cref="IApprovalAdmin.ApproveAsync"/> or <see cref="IApprovalAdmin.DenyAsync"/> call did.</summary>
public enum ApprovalDecisionOutcome
{
    /// <summary>The request was pending and this call settled it.</summary>
    Applied,

    /// <summary>The request exists but was already approved or denied, for example by a concurrent approver, so this
    /// call changed nothing.</summary>
    AlreadySettled,

    /// <summary>The store holds no request with this id.</summary>
    NotFound,
}
