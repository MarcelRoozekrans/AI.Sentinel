namespace AI.Sentinel.Approvals;

/// <summary>
/// Marks an <see cref="IApprovalStore"/> whose grants are role activations for a time window. Such a grant has no
/// notion of tool arguments, so it cannot be scoped to one call, and building the tool-call guard rejects an
/// <see cref="ApprovalGrantScope.Call"/> rule over a store that carries this marker.
/// </summary>
internal interface IRoleActivationApprovalStore
{
    /// <summary>The name of the backend, used in the startup error.</summary>
    string BackendName { get; }
}
