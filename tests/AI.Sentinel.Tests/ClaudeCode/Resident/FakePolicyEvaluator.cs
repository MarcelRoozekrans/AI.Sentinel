using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>An evaluator that answers, stays silent or fails, and counts its calls.</summary>
internal sealed class FakePolicyEvaluator(string place, Func<RegoDecision?> answer) : IPolicyEvaluator
{
    public string Place { get; } = place;

    public int Calls { get; private set; }

    public RegoDecision? Evaluate(string inputJson)
    {
        Calls++;
        return answer();
    }

    public static RegoDecision Deny(string reason) => new(DecisionOutcome.Deny, [reason]);
}
