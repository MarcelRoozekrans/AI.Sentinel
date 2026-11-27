using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>One event as the server's ingest endpoint reads it (#660, ADR-240): the allowlisted fields and nothing else. There is
/// no member for a command, a path or tool input, so none can be sent.</summary>
internal sealed record ForwardedEvent
{
    [JsonPropertyName("event_id")]
    public required string EventId { get; init; }

    [JsonPropertyName("at")]
    public required string At { get; init; }

    [JsonPropertyName("tool_kind")]
    public required string ToolKind { get; init; }

    [JsonPropertyName("outcome")]
    public required string Outcome { get; init; }

    [JsonPropertyName("policies")]
    public List<string>? Policies { get; init; }

    [JsonPropertyName("policy_version")]
    public string? PolicyVersion { get; init; }

    [JsonPropertyName("decided")]
    public string? Decided { get; init; }

    [JsonPropertyName("node")]
    public string? Node { get; init; }

    [JsonPropertyName("cli")]
    public string? Cli { get; init; }

    [JsonPropertyName("session")]
    public string? Session { get; init; }

    [JsonPropertyName("detector")]
    public string? Detector { get; init; }

    [JsonPropertyName("severity")]
    public string? Severity { get; init; }

    [JsonPropertyName("redactions")]
    public Dictionary<string, int>? Redactions { get; init; }

    /// <summary>Only with detailed logging, and then after <see cref="ReasonRedactor"/>.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; init; }
}
