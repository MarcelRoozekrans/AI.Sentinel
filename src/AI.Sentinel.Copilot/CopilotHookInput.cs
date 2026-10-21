using System.Text.Json;
using System.Text.Json.Serialization;

namespace AI.Sentinel.Copilot;

/// <summary>Payload a hook CLI reads from stdin. Optional members are init properties so new fields can be added without breaking callers.</summary>
public sealed record CopilotHookInput
{
    public string SessionId { get; init; } = string.Empty;
    public string? Prompt { get; init; }
    public string? ToolName { get; init; }
    public JsonElement? ToolInput { get; init; }
    public JsonElement? ToolResponse { get; init; }

    /// <summary>Tool arguments as Copilot sends them. Either a JSON object or a JSON string holding the arguments.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? ToolArgs { get; init; }

    /// <summary>Tool result as Copilot sends it, shaped {resultType, textResultForLlm}.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? ToolResult { get; init; }

    /// <summary>Prompt after Copilot has transformed it, when the hook event carries one.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TransformedPrompt { get; init; }

    [JsonIgnore]
    internal JsonElement? EffectiveToolArgs => ToolArgs ?? ToolInput;

    [JsonIgnore]
    internal JsonElement? EffectiveToolResult => ToolResult ?? ToolResponse;

    /// <summary>Copilot may send toolArgs as a JSON string; scan the decoded text, not the quoted and escaped raw form.</summary>
    internal string ToolArgsText() => EffectiveToolArgs is { } e ? ScanText(e) : "";

    internal string ToolResultText() => EffectiveToolResult is { } e ? ScanText(e) : "";

    /// <summary>The guard expects a JSON element; a string holding JSON is parsed so policies see the same shape either way.</summary>
    internal JsonElement GuardToolArgs(JsonElement fallback)
    {
        if (EffectiveToolArgs is not { } e)
        {
            return fallback;
        }

        if (e.ValueKind == JsonValueKind.String && e.GetString() is { } text)
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                return doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                return e;
            }
        }

        return e;
    }

    private static string ScanText(JsonElement e) =>
        e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : e.GetRawText();
}
