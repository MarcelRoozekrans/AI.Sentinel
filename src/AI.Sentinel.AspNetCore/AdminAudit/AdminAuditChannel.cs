namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>The channel an administrative action came through.</summary>
internal enum AdminAuditChannel
{
    Web,
    Mcp,
    Git,
}
