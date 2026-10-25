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

    /// <summary><c>session_id</c>, sent instead of <c>sessionId</c> by a hook configured with a PascalCase event name,
    /// which gets the VS Code compatible payload. Read only through <see cref="WithVsCodeAliases"/>.</summary>
    [JsonInclude]
    [JsonPropertyName("session_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    internal string? VsCodeSessionId { get; init; }

    /// <summary><c>tool_name</c> of the VS Code compatible payload: the Claude tool name, such as <c>Bash</c>.</summary>
    [JsonInclude]
    [JsonPropertyName("tool_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    internal string? VsCodeToolName { get; init; }

    /// <summary><c>tool_input</c> of the VS Code compatible payload.</summary>
    [JsonInclude]
    [JsonPropertyName("tool_input")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    internal JsonElement? VsCodeToolInput { get; init; }

    /// <summary><c>tool_result</c> of the VS Code compatible payload, shaped
    /// <c>{result_type, text_result_for_llm}</c>.</summary>
    [JsonInclude]
    [JsonPropertyName("tool_result")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    internal JsonElement? VsCodeToolResult { get; init; }

    /// <summary>True when <see cref="ToolName"/> came from <c>tool_name</c>, which carries the Claude tool name.</summary>
    [JsonIgnore]
    internal bool UsesClaudeToolNames { get; private init; }

    /// <summary>
    /// This input with the VS Code compatible snake_case fields copied onto the members the adapter reads. A camelCase
    /// field wins when both are sent. Returns this instance when no snake_case field was sent.
    /// </summary>
    internal CopilotHookInput WithVsCodeAliases()
    {
        if (VsCodeSessionId is null && VsCodeToolName is null && VsCodeToolInput is null && VsCodeToolResult is null)
        {
            return this;
        }

        var toolNameFromAlias = ToolName is null && VsCodeToolName is not null;
        return this with
        {
            SessionId = string.IsNullOrEmpty(SessionId) ? VsCodeSessionId ?? SessionId : SessionId,
            ToolName = ToolName ?? VsCodeToolName,
            ToolInput = ToolInput ?? VsCodeToolInput,
            ToolResult = ToolResult ?? VsCodeToolResult,
            UsesClaudeToolNames = UsesClaudeToolNames || toolNameFromAlias,
        };
    }

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

        if (e.ValueKind == JsonValueKind.String)
        {
            try
            {
                using var doc = JsonDocument.Parse(e.GetString() ?? "");
                return doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                return e;
            }
            catch (InvalidOperationException)
            {
                // The string holds an escape that does not decode, such as a lone surrogate. Hand the guard the
                // string element itself: arguments that are not structured satisfy every condition, so it fails closed.
                return e;
            }
        }

        return e;
    }

    private static string ScanText(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.String)
        {
            return e.GetRawText();
        }

        try
        {
            return e.GetString() ?? "";
        }
        catch (InvalidOperationException)
        {
            // A string that does not decode, such as one holding a lone surrogate escape, is scanned as its raw JSON text.
            return e.GetRawText();
        }
    }
}
