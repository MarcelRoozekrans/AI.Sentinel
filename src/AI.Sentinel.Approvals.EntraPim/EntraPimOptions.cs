namespace AI.Sentinel.Approvals.EntraPim;

/// <summary>
/// Configuration for <see cref="EntraPimApprovalStore"/>. The store is wired via
/// <c>AddSentinelEntraPimApprovalStore(opts =&gt; ...)</c> (see Task 2.5).
/// </summary>
public sealed class EntraPimOptions
{
    /// <summary>Entra ID tenant ID (GUID). Required.</summary>
    /// <remarks>
    /// Mutable (<c>set;</c>) rather than <c>init;</c> so the
    /// <c>AddSentinelEntraPimApprovalStore(opts =&gt; ...)</c> configure delegate can
    /// assign it after construction (matches the Task 1.6 <c>ApprovalSpec</c> pattern).
    /// The <c>required</c> modifier still enforces it at construction time.
    /// </remarks>
    public required string TenantId { get; set; }

    /// <summary>Initial poll interval for <c>WaitForDecisionAsync</c>. Doubles on each
    /// iteration up to <see cref="PollMaxBackoff"/>, with ±20% jitter.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Upper bound on the polling backoff schedule.</summary>
    public TimeSpan PollMaxBackoff { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Pre-resolved role display-name → roleDefinitionId mappings. Lookups skip the Graph
    /// round-trip when the role is in this seed. Empty by default; the store resolves on
    /// first use and caches for the process lifetime.
    /// </summary>
    /// <remarks>
    /// Snapshot semantics: the seed is copied into the store's internal cache at
    /// construction, so post-construction mutations to this dictionary do NOT propagate.
    /// Exposed as <see cref="IReadOnlyDictionary{TKey, TValue}"/> with <c>init;</c> to
    /// make that contract explicit — callers should whole-replace via object initialiser
    /// rather than expect mutation semantics.
    /// </remarks>
    public IReadOnlyDictionary<string, string> RoleNameToIdSeed { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Portal base URL for the approval link sent back to the requester. Defaults to
    /// Azure commercial cloud. Sovereign clouds: Azure Gov uses
    /// <c>https://portal.azure.us</c>, Azure China <c>https://portal.azure.cn</c>,
    /// Azure Germany <c>https://portal.microsoftazure.de</c>.
    /// </summary>
    public string PortalBaseUrl { get; set; } = "https://portal.azure.com";
}
