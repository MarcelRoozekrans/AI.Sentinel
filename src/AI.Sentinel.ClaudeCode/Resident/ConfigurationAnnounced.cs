using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The data of a <see cref="SessionEventNames.Configuration"/> event: a configuration came into force.</summary>
internal sealed record ConfigurationAnnounced([property: JsonPropertyName("version")] long Version);
