using System.Net;

namespace AI.Sentinel.Cli;

/// <summary>Validated options for <c>sentinel dashboard</c>.</summary>
internal sealed record DashboardSettings(string DbPath, int Port)
{
    /// <summary>The header a trusted proxy sets to the authenticated user name, unless <c>--user-header</c> says otherwise.</summary>
    internal const string DefaultUserHeader = "X-Auth-Request-User";

    public IPAddress Bind { get; init; } = IPAddress.Loopback;
    public string? ApprovalConfigPath { get; init; }
    public bool ApprovalConfigExplicit { get; init; }
    public IReadOnlyList<IPNetwork> TrustedProxies { get; init; } = [];
    public string UserHeader { get; init; } = DefaultUserHeader;
    public bool LocalApprover { get; init; }
}
