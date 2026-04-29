namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>Snapshot of a role-assignment schedule. <c>Status</c> follows PIM's
/// <c>roleAssignmentSchedules</c> status vocabulary (e.g. <c>Provisioned</c>).</summary>
public sealed record RoleScheduleSnapshot(string Status, DateTimeOffset? ExpiresAt);
