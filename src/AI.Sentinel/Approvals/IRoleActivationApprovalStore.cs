namespace AI.Sentinel.Approvals;

/// <summary>
/// Marks an <see cref="IApprovalStore"/> whose grants are role activations for a time window. Such a grant has no
/// notion of tool arguments, so it cannot be scoped to one call, and building the tool-call guard rejects an
/// <see cref="ApprovalGrantScope.Call"/> rule over a store that carries this marker: it throws when the tool-call
/// guard is first resolved. The check sees through AI.Sentinel's own auditing wrapper only; a custom decorator
/// around the store hides the marker.
/// </summary>
internal interface IRoleActivationApprovalStore
{
    /// <summary>The name of the backend, used in the error thrown when the tool-call guard is first resolved.</summary>
    string BackendName { get; }
}
