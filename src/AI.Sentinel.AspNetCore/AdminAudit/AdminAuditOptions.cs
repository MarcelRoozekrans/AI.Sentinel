namespace AI.Sentinel.AspNetCore;

/// <summary>Settings of the administrative audit log. Nothing is registered or mapped unless the host calls
/// <see cref="AdminAuditExtensions.AddAISentinelAdminAudit"/> and <see cref="AdminAuditExtensions.MapAISentinelAdminAudit"/>.</summary>
public sealed class AdminAuditOptions
{
    /// <summary>The name of the ASP.NET Core authorization policy the export endpoint requires. The organisation is passed
    /// as the resource, as a string. The host defines the policy. Defaults to <c>AISentinelAdminAudit</c>.</summary>
    public string PolicyName { get; set; } = "AISentinelAdminAudit";

    /// <summary>The deployment's Ed25519 signing key: the base64 of a 32 byte seed. It signs the head of each export.
    /// It reaches the server through the deployment at startup and is never stored. Required.</summary>
    public string? SigningKey { get; set; }
}
