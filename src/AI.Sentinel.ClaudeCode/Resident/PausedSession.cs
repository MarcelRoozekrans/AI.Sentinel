using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>A pause: while it lasts, every tool call of the named session is denied.</summary>
/// <param name="Session">The session id the pause names.</param>
/// <param name="Reason">Why, shown to the developer; <see langword="null"/> for none.</param>
/// <param name="Until">When the pause ends; <see langword="null"/> for a pause that lasts until it is lifted.</param>
internal sealed record PausedSession(
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("until")] DateTimeOffset? Until);
