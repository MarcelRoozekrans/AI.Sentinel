namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>An administrative action the server part records (ADR-241).</summary>
internal enum AdminAuditAction
{
    Approve,
    Deny,
    Pause,
    Release,
    Publish,
    RejectedPublish,
    Rollback,
}
