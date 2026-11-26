namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>Stable wire names for the audit log. Written by hand: no reflection, so the names never change with a rename.</summary>
internal static class AdminAuditNames
{
    public static string Of(AdminAuditAction action) => action switch
    {
        AdminAuditAction.Approve => "approve",
        AdminAuditAction.Deny => "deny",
        AdminAuditAction.Pause => "pause",
        AdminAuditAction.Release => "release",
        AdminAuditAction.Publish => "publish",
        AdminAuditAction.RejectedPublish => "rejected_publish",
        AdminAuditAction.Rollback => "rollback",
        _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unknown administrative action."),
    };

    public static string Of(AdminAuditChannel channel) => channel switch
    {
        AdminAuditChannel.Web => "web",
        AdminAuditChannel.Mcp => "mcp",
        AdminAuditChannel.Git => "git",
        _ => throw new ArgumentOutOfRangeException(nameof(channel), channel, "Unknown channel."),
    };

    public static bool IsKnownAction(string? name) =>
        name is "approve" or "deny" or "pause" or "release" or "publish" or "rejected_publish" or "rollback";

    public static bool IsKnownChannel(string? name) => name is "web" or "mcp" or "git";
}
