using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.SessionControl;

/// <summary>A pause in force, as the list endpoint shows it to a team lead of its node.</summary>
internal sealed record PauseListEntry(
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("repository")] string Repository,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("until")] DateTimeOffset? Until);
