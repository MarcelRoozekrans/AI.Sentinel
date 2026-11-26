using System.Diagnostics;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Evaluates through the resident process, which keeps the module loaded. The budget is one for the whole call: the time every
/// exchange takes is added up, an exchange gets what is left, and after one gets no answer, or the budget is spent, this evaluator
/// stays silent for the rest of that call.
/// </summary>
internal sealed class ResidentPolicyEvaluator(ResidentClient client, string folder, string version, string cacheDirectory) : IPolicyEvaluator
{
    private bool _missed;
    private TimeSpan _spent;

    public string Place => OutcomeDecision.Resident;

    public RegoDecision? Evaluate(string inputJson)
    {
        if (_missed)
        {
            return null;
        }

        var left = client.Settings.Budget - _spent;
        if (left <= TimeSpan.Zero)
        {
            _missed = true;
            return null;
        }

        var started = Stopwatch.GetTimestamp();
        var decision = client.Evaluate(folder, version, cacheDirectory, inputJson, left);
        _spent += Stopwatch.GetElapsedTime(started);
        _missed = decision is null;
        return decision;
    }
}
