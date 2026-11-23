using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>One place a policy can be evaluated: the resident process, the hook itself, or the server.</summary>
internal interface IPolicyEvaluator
{
    /// <summary>Where the evaluation happens, one of <see cref="OutcomeDecision.Resident"/>, <see cref="OutcomeDecision.InProcess"/>
    /// and <see cref="OutcomeDecision.Server"/>.</summary>
    string Place { get; }

    /// <summary>The decision, or <see langword="null"/> when this place has no answer within its budget. A failure throws.</summary>
    RegoDecision? Evaluate(string inputJson);
}
