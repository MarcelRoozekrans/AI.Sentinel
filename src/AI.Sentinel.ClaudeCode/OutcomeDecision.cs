using System.Text;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// One decision with its outcome, the reason, the sources that caused it, the policy version and where it was made.
/// </summary>
/// <param name="Outcome">The outcome.</param>
/// <param name="Reason">Why. Shown to the developer or the agent, so it holds no secret.</param>
/// <param name="Sources">Names of the sources that caused the outcome, such as a bundle, the approval config or
/// <c>SENTINEL_HOOK_ON_HIGH</c>.</param>
/// <param name="PolicyVersion">The policy version; empty until policy exists.</param>
/// <param name="DecidedAt">Where the decision was made, such as <see cref="InProcess"/>.</param>
internal sealed record OutcomeDecision(
    DecisionOutcome Outcome,
    string Reason,
    IReadOnlyList<string> Sources,
    string PolicyVersion = "",
    string DecidedAt = OutcomeDecision.InProcess)
{
    /// <summary>The decision was made in the hook process.</summary>
    public const string InProcess = "in-process";

    /// <summary>The decision was made by the resident local process (#658).</summary>
    public const string Resident = "resident";

    /// <summary>The decision was made by the server, when neither the resident process nor the hook could evaluate the module.</summary>
    public const string Server = "server";

    /// <summary>The strictest of <paramref name="decisions"/>. When several share the strictest outcome their sources are
    /// joined, in order and without repeats, and their reasons are joined with a semicolon. The policy version and place
    /// are those of the first of them.</summary>
    public static OutcomeDecision Strictest(IReadOnlyList<OutcomeDecision> decisions)
    {
        ArgumentNullException.ThrowIfNull(decisions);
        if (decisions.Count == 0)
        {
            throw new ArgumentException("At least one decision is needed.", nameof(decisions));
        }

        var strictest = decisions[0].Outcome;
        foreach (var d in decisions)
        {
            strictest = DecisionOutcomes.Strictest(strictest, d.Outcome);
        }

        OutcomeDecision? first = null;
        var reasons = new List<string>();
        var sources = new List<string>();
        foreach (var d in decisions)
        {
            if (d.Outcome != strictest)
            {
                continue;
            }

            first ??= d;
            if (!string.IsNullOrEmpty(d.Reason) && !reasons.Contains(d.Reason, StringComparer.Ordinal))
            {
                reasons.Add(d.Reason);
            }

            foreach (var s in d.Sources)
            {
                if (!sources.Contains(s, StringComparer.Ordinal))
                {
                    sources.Add(s);
                }
            }
        }

        return first! with { Reason = string.Join("; ", reasons), Sources = sources };
    }

    /// <summary>The decision for a legacy severity action, with <paramref name="source"/> as its only source.</summary>
    public static OutcomeDecision FromHook(HookDecision decision, string? reason, string source) =>
        new(DecisionOutcomes.FromHook(decision), reason ?? string.Empty, [source]);

    /// <summary>The audit summary: <c>deny: reason; sources=a,b; policy=v1; decided=in-process</c>.</summary>
    public string Summary()
    {
        var sb = new StringBuilder(DecisionOutcomes.Name(Outcome)).Append(": ").Append(Reason)
            .Append("; sources=").Append(string.Join(',', Sources))
            .Append("; policy=").Append(PolicyVersion)
            .Append("; decided=").Append(DecidedAt);
        return sb.ToString();
    }

    /// <summary>The deny an ask becomes where the CLI cannot ask or the run is headless: the reason, then what to do.</summary>
    public OutcomeDecision AskAsDeny() =>
        this with
        {
            Outcome = DecisionOutcome.Deny,
            Reason = $"{Reason} AI.Sentinel needs a person to confirm this call, and this run cannot ask. "
                + "Explain to the developer what the command does and why it is needed, then let the developer run it "
                + "or ask a policy owner to allow it.",
        };

    /// <summary>The <see cref="HookOutput"/> for this decision. An ask that <paramref name="canAsk"/> says cannot be
    /// expressed becomes a deny with instructions.</summary>
    public HookOutput ToHookOutput(bool canAsk)
    {
        var decision = Outcome == DecisionOutcome.Ask && !canAsk ? AskAsDeny() : this;
        return new HookOutput
        {
            Decision = DecisionOutcomes.ToHook(decision.Outcome),
            Reason = string.IsNullOrEmpty(decision.Reason) ? null : decision.Reason,
            Outcome = decision,
        };
    }
}
