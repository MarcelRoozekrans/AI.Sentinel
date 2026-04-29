namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>Snapshot of a role-assignment-schedule request. <c>Status</c> follows PIM's
/// request status vocabulary (e.g. <c>PendingApproval</c>, <c>Provisioned</c>, <c>Failed</c>).
/// </summary>
/// <remarks>
/// <see cref="PrincipalId"/> / <see cref="RoleId"/> identify the request's subject and role.
/// The store uses them to re-query the matching schedule for an authoritative <c>ExpiresAt</c>
/// when the request transitions to Provisioned. Production Graph adapters populate these from
/// the request entity; tests can leave them null for paths that don't exercise schedule-readback.
/// </remarks>
internal sealed record RoleRequestSnapshot(
    string Status,
    string? FailureReason,
    string? PrincipalId = null,
    string? RoleId = null);
