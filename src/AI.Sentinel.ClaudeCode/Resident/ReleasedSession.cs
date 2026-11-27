using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The data of a <see cref="SessionEventNames.Release"/> event.</summary>
internal sealed record ReleasedSession([property: JsonPropertyName("session")] string Session);
