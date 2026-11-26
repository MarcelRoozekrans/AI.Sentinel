using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.AdminAudit;

internal sealed class AdminAuditEntryWire
{
    [JsonPropertyName("id")]
    public string? Id { get; init; }

    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; init; }

    [JsonPropertyName("organisation")]
    public string? Organisation { get; init; }

    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("actor")]
    public string? Actor { get; init; }

    [JsonPropertyName("target")]
    public string? Target { get; init; }

    [JsonPropertyName("channel")]
    public string? Channel { get; init; }

    [JsonPropertyName("previous_hash")]
    public string? PreviousHash { get; init; }

    [JsonPropertyName("hash")]
    public string? Hash { get; init; }
}
