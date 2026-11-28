using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// The policy that applies to a call is the policy of the node that owns the repository, not of the developer's team (ADR-232,
/// ADR-246). <see cref="HookProfiles.Open"/> resolves the repository of the working directory and its node, which fill the policy
/// input, and this judges the call by the organisation's top-level rules and, unless no node owns the repository, the node's bundle.
/// Every decision is combined with the others strictest-wins, so a bundle can only tighten what the organisation set.
/// </summary>
internal sealed class RepositoryPolicy(RepositoryScope scope, INodePolicies policies)
{
    /// <summary>The source the organisation's top-level rules are named by.</summary>
    public const string OrganisationSource = "organisation";

    /// <summary>The prefix of the source a node's bundle is named by, followed by the node.</summary>
    public const string NodeSourcePrefix = "node:";

    /// <summary>Where and by whom the calls of this process run.</summary>
    public RepositoryScope Scope { get; } = scope;

    /// <summary>The decisions of the organisation's rules and of the node's bundle for <paramref name="inputJson"/>, the ones that
    /// have an opinion. The bundle of an unowned repository is never consulted, so strict mode gives the organisation's rules only.</summary>
    public IReadOnlyList<OutcomeDecision> Decisions(string inputJson) => Evaluate(inputJson).Decisions;

    /// <summary>As <see cref="Decisions"/>, and whether a profile module failed while it ran. That ends the order (ADR-237): the
    /// denial names that bundle, and no later bundle, and no local folder, is evaluated after it.</summary>
    public (IReadOnlyList<OutcomeDecision> Decisions, bool BundleFailed) Evaluate(string inputJson)
    {
        ArgumentNullException.ThrowIfNull(inputJson);
        var decisions = new List<OutcomeDecision>(2);
        if (!Add(decisions, () => policies.Organisation(inputJson), OrganisationSource))
        {
            return (decisions, true);
        }

        if (!Scope.Unowned && !Add(decisions, () => policies.ForRepository(Scope.Repository, inputJson), NodeSourcePrefix + Scope.Node))
        {
            return (decisions, true);
        }

        return (decisions, false);
    }

    /// <summary>The denial of a profile module that failed while it ran (ADR-237): by name, whatever the fail mode. The message of the
    /// error is left out, a module that aborts may echo what it was given.</summary>
    internal static OutcomeDecision BundleError(string source) =>
        new(
            DecisionOutcome.Deny,
            $"The policy bundle {source} failed while it ran, so this call is denied whatever the fail mode. Ask a policy owner to fix the bundle.",
            [source]);

    // False when the module failed while it ran: its denial is added and the order ends.
    private static bool Add(List<OutcomeDecision> decisions, Func<RegoDecision?> decide, string source)
    {
        RegoDecision? decision;
        try
        {
            decision = decide();
        }
        catch (PolicyBundleException)
        {
            decisions.Add(BundleError(source));
            return false;
        }

        if (decision is { Outcome: not DecisionOutcome.Defer })
        {
            decisions.Add(new OutcomeDecision(decision.Outcome, string.Join("; ", decision.Reasons), [decision.Refused is { } builtin ? "builtin:" + builtin : source]));
        }

        return true;
    }
}
