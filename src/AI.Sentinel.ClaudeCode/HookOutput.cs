using System.Text.Json;
using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode;

/// <summary>Result a hook CLI writes to stdout. <see cref="Decision"/> is always present; every other member is optional.</summary>
public sealed record HookOutput
{
    public required HookDecision Decision { get; init; }
    public string? Reason { get; init; }

    /// <summary>The tool output the model should see instead of the original, for a tool-result event: a copy whose
    /// string values hold placeholders instead of sensitive values, or, on <see cref="HookDecision.Block"/>, the withheld
    /// body. For Claude Code that body keeps the shape of the tool output, with its string values replaced by the
    /// withheld text, and is the withheld text itself only when the output is not an object or an array; for Copilot it is
    /// always the withheld text as a JSON string. <see langword="null"/> when the output is delivered as it is.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? UpdatedToolOutput { get; init; }

    /// <summary>Entity type to number of redacted occurrences in <see cref="UpdatedToolOutput"/>, such as
    /// <c>EMAIL</c> to 1. Counts only, never a value. <see langword="null"/> when nothing was redacted.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, int>? Redactions { get; init; }
}
