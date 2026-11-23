namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>A detector finding the policy can match on.</summary>
/// <param name="Detector">Detector id, such as SEC-01.</param>
/// <param name="Severity">Severity name in lower case.</param>
internal sealed record PolicyFinding(string Detector, string Severity);
