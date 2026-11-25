using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>A decision and the place it was made.</summary>
/// <param name="Decision">The decision.</param>
/// <param name="Place">One of <see cref="OutcomeDecision.Resident"/>, <see cref="OutcomeDecision.InProcess"/> and <see cref="OutcomeDecision.Server"/>.</param>
internal sealed record PolicyAnswer(RegoDecision Decision, string Place);
