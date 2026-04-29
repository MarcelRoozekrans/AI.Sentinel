namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>
/// Configuration for <see cref="EntraPimApprovalStore"/>. The store is wired via
/// <c>AddSentinelEntraPimApprovalStore(opts =&gt; ...)</c> (see Task 2.5).
/// </summary>
public sealed class EntraPimOptions
{
    /// <summary>Entra ID tenant ID (GUID). Required.</summary>
    public required string TenantId { get; init; }

    /// <summary>Initial poll interval for <c>WaitForDecisionAsync</c>. Doubles on each
    /// iteration up to <see cref="PollMaxBackoff"/>, with ±20% jitter.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Upper bound on the polling backoff schedule.</summary>
    public TimeSpan PollMaxBackoff { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Pre-resolved role display-name → roleDefinitionId mappings. Lookups skip the Graph
    /// round-trip when the role is in this seed. Empty by default; the store resolves on
    /// first use and caches for the process lifetime.
    /// </summary>
    public IDictionary<string, string> RoleNameToIdSeed { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
