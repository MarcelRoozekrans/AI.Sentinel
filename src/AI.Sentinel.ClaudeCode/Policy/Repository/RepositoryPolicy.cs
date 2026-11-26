using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// The policy that applies to a call is the policy of the node that owns the repository, not of the developer's team (ADR-232,
/// ADR-246). This resolves the repository of the working directory and its node, fills the policy input with them, and judges the
/// call by the organisation's top-level rules and, unless the repository is in strict mode, the node's bundle. Every decision is
/// combined with the others strictest-wins, so a bundle can only tighten what the organisation set.
/// </summary>
internal sealed class RepositoryPolicy(RepositoryScope scope, INodePolicies policies)
{
    /// <summary>The source the organisation's top-level rules are named by.</summary>
    public const string OrganisationSource = "organisation";

    /// <summary>The prefix of the source a node's bundle is named by, followed by the node.</summary>
    public const string NodeSourcePrefix = "node:";

    /// <summary>Where and by whom the calls of this process run.</summary>
    public RepositoryScope Scope { get; } = scope;

    /// <summary>The repository policy when a node map is cached, or <see langword="null"/> and then nothing is resolved and the
    /// input names no repository, as before. A cached map is only written once the PC has a server, so without one nothing changes.
    /// Strict repository mode is on unless <see cref="RepositoryScope.StrictVariable"/> switches it off.</summary>
    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="workingDirectory">The working directory of the hook.</param>
    /// <exception cref="InvalidDataException">The cached map cannot be read; the hook blocks the call.</exception>
    public static RepositoryPolicy? Open(IReadOnlyDictionary<string, string?> env, string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (Resident.ResidentSettings.FromEnvironment(env) is not { } settings
            || Resident.ResidentState.Open(settings).ReadNodeMap() is not { } map)
        {
            return null;
        }

        return new RepositoryPolicy(RepositoryScope.Resolve(workingDirectory, map, RepositoryScope.StrictFrom(env)), NoNodePolicies.Instance);
    }

    /// <summary>The decisions of the organisation's rules and of the node's bundle for <paramref name="inputJson"/>, the ones that
    /// have an opinion. The bundle of an unowned repository is never consulted, so strict mode gives the organisation's rules only.</summary>
    public IReadOnlyList<OutcomeDecision> Decisions(string inputJson)
    {
        ArgumentNullException.ThrowIfNull(inputJson);
        var decisions = new List<OutcomeDecision>(2);
        Add(decisions, policies.Organisation(inputJson), OrganisationSource);
        if (!Scope.Unowned)
        {
            Add(decisions, policies.ForRepository(Scope.Repository, inputJson), NodeSourcePrefix + Scope.Node);
        }

        return decisions;
    }

    private static void Add(List<OutcomeDecision> decisions, RegoDecision? decision, string source)
    {
        if (decision is { Outcome: not DecisionOutcome.Defer })
        {
            decisions.Add(new OutcomeDecision(decision.Outcome, string.Join("; ", decision.Reasons), [decision.Refused is { } builtin ? "builtin:" + builtin : source]));
        }
    }
}
