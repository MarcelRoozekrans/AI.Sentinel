using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>What the server sends first on the event stream, and again after every reconnect: the pauses in force and the version of
/// the configuration in force, so a resident process that missed events catches up.</summary>
/// <param name="ConfigurationVersion">The configuration in force; <see langword="null"/> before one has been published.</param>
/// <param name="Pauses">Every pause in force. A session that is not in it is not paused.</param>
internal sealed record SessionSnapshot(
    [property: JsonPropertyName("configuration_version")] long? ConfigurationVersion,
    [property: JsonPropertyName("pauses")] PausedSession[] Pauses);
