using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The outcome a policy sets for one finding severity, as it travels on the local channel.</summary>
/// <param name="Severity">The severity name.</param>
/// <param name="Outcome">The outcome name.</param>
internal sealed record ResidentSeverity(
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("outcome")] string Outcome);
