namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>A node of the configuration and what it settles: the organisation or a team (ADR-232).</summary>
internal sealed record ConfiguredNode(
    string Id, bool IsOrganisation, string FailMode, TimeSpan? ProfileLifetime, bool DetailedLogging,
    IReadOnlyDictionary<string, string> SeverityDefaults,
    string? NamesApproval = null)
{
    /// <summary>Whether the events endpoints may show a code per developer for this node. Only with an approval reference.</summary>
    public bool ShowNames => NamesApproval is not null;
}
