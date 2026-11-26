using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>The cached policies a call is judged by, read with no network. The seam a test replaces.</summary>
internal interface INodePolicies
{
    /// <summary>The decision of the organisation's top-level rules; <see langword="null"/> when none are cached.</summary>
    RegoDecision? Organisation(string inputJson);

    /// <summary>The decision of the bundle of the node that owns <paramref name="repository"/>; <see langword="null"/> when none is
    /// cached or the cached one is not usable.</summary>
    RegoDecision? ForRepository(string repository, string inputJson);
}
