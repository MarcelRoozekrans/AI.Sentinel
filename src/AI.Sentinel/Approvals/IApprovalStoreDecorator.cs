namespace AI.Sentinel.Approvals;

/// <summary>
/// An <see cref="IApprovalStore"/> that wraps another one. Code that needs the store underneath the wrappers follows
/// <see cref="Inner"/> until it reaches a store that is not a decorator.
/// </summary>
internal interface IApprovalStoreDecorator
{
    /// <summary>The store this decorator wraps.</summary>
    IApprovalStore Inner { get; }
}
