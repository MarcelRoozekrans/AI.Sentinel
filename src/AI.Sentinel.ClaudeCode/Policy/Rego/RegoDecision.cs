namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>What the policy returned for one tool call: an outcome and the reasons behind it.</summary>
/// <param name="Outcome">The outcome; <see cref="DecisionOutcome.Defer"/> when no bundle had an opinion.</param>
/// <param name="Reasons">The reasons of the winning outcome, in the order OPA sorts them.</param>
/// <param name="SeverityActions">The outcomes the policy sets per finding severity; <see cref="ClaudeCode.SeverityActions.None"/> when it sets none.</param>
/// <param name="Refused">The builtin the call met that the host does not run, when that is why the outcome is a deny.</param>
internal sealed record RegoDecision(DecisionOutcome Outcome, IReadOnlyList<string> Reasons, string? Refused = null, SeverityActions? SeverityActions = null);
