using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>A pause: while it lasts, every tool call of the named session is denied. It names a session, never a person.</summary>
/// <param name="Session">The session id the pause names.</param>
/// <param name="Reason">Why, shown to the developer; <see langword="null"/> for none.</param>
/// <param name="Until">When the pause ends; <see langword="null"/> for a pause that lasts until it is lifted.</param>
internal sealed record PausedSession(
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("until")] DateTimeOffset? Until)
{
    /// <summary>What the agent is told when a call of the paused session is denied: a team lead paused the session, and the agent has to
    /// stop and hand control back to the developer, not retry.</summary>
    public string DenyReason() =>
        "AI.Sentinel: a team lead paused this session. Stop, tell the developer, and wait until it is released; do not retry or work around it."
        + (string.IsNullOrWhiteSpace(Reason) ? string.Empty : $" Reason: {Reason}");

    /// <summary>Whether the pause still holds at <paramref name="now"/>.</summary>
    public bool IsActive(DateTimeOffset now) => Until is null || now < Until;
}
