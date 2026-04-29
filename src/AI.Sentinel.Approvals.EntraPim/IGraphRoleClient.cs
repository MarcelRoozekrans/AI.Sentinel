namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>
/// Narrow Graph-API surface used by <see cref="EntraPimApprovalStore"/>. Production
/// implementation: <c>MicrosoftGraphRoleClient</c> (Task 2.4). Unit tests fake this
/// interface so the store's logic is testable without hitting Graph.
/// </summary>
internal interface IGraphRoleClient
{
    /// <summary>Resolves a role display name to its Entra <c>roleDefinitionId</c>.
    /// Returns null if the role doesn't exist in the tenant.</summary>
    ValueTask<string?> ResolveRoleIdAsync(string displayName, CancellationToken ct);

    /// <summary>Returns the active assignment schedule for the (principal, role) pair,
    /// or null if no Provisioned schedule is currently in force.</summary>
    ValueTask<RoleScheduleSnapshot?> GetActiveAssignmentAsync(
        string principalId, string roleId, CancellationToken ct);

    /// <summary>True if the principal is eligible to activate the role
    /// (has a roleEligibilitySchedule).</summary>
    ValueTask<bool> IsEligibleAsync(string principalId, string roleId, CancellationToken ct);

    /// <summary>Creates a <c>selfActivate</c> activation request. Returns the new request ID.</summary>
    ValueTask<string> CreateActivationRequestAsync(
        string principalId, string roleId, TimeSpan duration, string justification, CancellationToken ct);

    /// <summary>Reads the current status of a previously created activation request.</summary>
    ValueTask<RoleRequestSnapshot> GetRequestStatusAsync(string requestId, CancellationToken ct);
}
