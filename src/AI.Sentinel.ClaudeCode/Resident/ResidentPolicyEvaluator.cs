using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Evaluates through the resident process, which keeps the module loaded. After one evaluation of a call gets no answer in its
/// budget this evaluator stays silent for the rest of that call, so the budget is spent once per call and not once per evaluation.
/// </summary>
internal sealed class ResidentPolicyEvaluator(ResidentClient client, string folder, string version, string cacheDirectory) : IPolicyEvaluator
{
    private bool _missed;

    public string Place => OutcomeDecision.Resident;

    public RegoDecision? Evaluate(string inputJson)
    {
        if (_missed)
        {
            return null;
        }

        var decision = client.Evaluate(folder, version, cacheDirectory, inputJson);
        _missed = decision is null;
        return decision;
    }
}
