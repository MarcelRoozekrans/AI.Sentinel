using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Carries a <see cref="RegoDecision"/> over the local channel and back.</summary>
internal static class ResidentDecisionWire
{
    public static ResidentResponse ToResponse(RegoDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        return new ResidentResponse
        {
            Ok = true,
            Pid = Environment.ProcessId,
            Outcome = DecisionOutcomes.Name(decision.Outcome),
            Reasons = decision.Reasons,
            Refused = decision.Refused,
            Severities = (decision.SeverityActions ?? SeverityActions.None).Entries().Select(e => new ResidentSeverity(e.Key, e.Value)).ToList(),
        };
    }

    /// <summary>The answer for a bundle that failed while it ran: the type of the error, never its message, which may echo the input.</summary>
    public static ResidentResponse ToBundleError(Exception error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new ResidentResponse { Pid = Environment.ProcessId, BundleError = true, Error = error.GetType().Name };
    }

    /// <summary>The decision of an answer, or <see langword="null"/> when the answer is not a decision.</summary>
    /// <exception cref="PolicyBundleException">The bundle failed while it ran in the resident process; the hook denies that by name.</exception>
    public static RegoDecision? FromResponse(ResidentResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.BundleError)
        {
            throw PolicyBundleException.FromResident(response.Error);
        }

        if (!response.Ok || response.Reasons is null || OutcomeOf(response.Outcome) is not { } outcome)
        {
            return null;
        }

        var severities = SeverityActions.Parse((response.Severities ?? []).Select(s => new KeyValuePair<string, string>(s.Severity, s.Outcome)));
        return new RegoDecision(outcome, response.Reasons, response.Refused, severities);
    }

    private static DecisionOutcome? OutcomeOf(string? name) => name switch
    {
        "deny" => DecisionOutcome.Deny,
        "ask" => DecisionOutcome.Ask,
        "guidance" => DecisionOutcome.Guidance,
        "allow" => DecisionOutcome.Allow,
        "defer" => DecisionOutcome.Defer,
        _ => null,
    };
}
