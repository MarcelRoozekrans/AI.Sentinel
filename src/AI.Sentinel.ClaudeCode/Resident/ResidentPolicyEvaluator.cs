using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Evaluates through the resident process, which keeps the module loaded. The budget is one for the whole call, shared with the
/// profile evaluations of that call (<see cref="ResidentBudget"/>): after one exchange gets no answer, or the budget is spent, this
/// evaluator stays silent for the rest of that call. A bundle that failed while it ran there is no silence: it throws
/// <see cref="PolicyBundleException"/>, which the hook denies by bundle name (ADR-237).
/// </summary>
internal sealed class ResidentPolicyEvaluator(ResidentClient client, string folder, string version, string cacheDirectory, ResidentBudget? budget = null) : IPolicyEvaluator
{
    private readonly ResidentBudget _budget = budget ?? new ResidentBudget(client.Settings.Budget);

    public string Place => OutcomeDecision.Resident;

    // A bundle that failed while it ran throws PolicyBundleException out of here, which ends the evaluation order (#716).
    public RegoDecision? Evaluate(string inputJson) =>
        _budget.Spend(left => client.Evaluate(folder, version, cacheDirectory, inputJson, left));
}
