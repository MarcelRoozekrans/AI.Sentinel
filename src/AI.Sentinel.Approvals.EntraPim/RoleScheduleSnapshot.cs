namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>Snapshot of a role-assignment schedule. <c>Status</c> follows PIM's
/// <c>roleAssignmentSchedules</c> status vocabulary (e.g. <c>Provisioned</c>). <c>RequestId</c> is the
/// schedule's <c>createdUsing</c>: the schedule request that created it, when Graph reports one.</summary>
internal sealed record RoleScheduleSnapshot(string Status, DateTimeOffset? ExpiresAt, string? RequestId = null);
