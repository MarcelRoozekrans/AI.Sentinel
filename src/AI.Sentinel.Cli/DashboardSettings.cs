using System.Net;

namespace AI.Sentinel.Cli;

/// <summary>Validated options for <c>sentinel dashboard</c>.</summary>
internal sealed record DashboardSettings(string DbPath, int Port)
{
    public IPAddress Bind { get; init; } = IPAddress.Loopback;
    public string? ApprovalConfigPath { get; init; }
    public bool ApprovalConfigExplicit { get; init; }
    public IReadOnlyList<IPNetwork> TrustedProxies { get; init; } = [];
    public string UserHeader { get; init; } = "X-Auth-Request-User";
    public bool LocalApprover { get; init; }
}
