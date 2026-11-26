using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>The policies of a PC that has no signed profile cached yet: nothing has an opinion. The profiles come with sign-in.</summary>
internal sealed class NoNodePolicies : INodePolicies
{
    public static readonly NoNodePolicies Instance = new();

    public RegoDecision? Organisation(string inputJson) => null;

    public RegoDecision? ForRepository(string repository, string inputJson) => null;
}
