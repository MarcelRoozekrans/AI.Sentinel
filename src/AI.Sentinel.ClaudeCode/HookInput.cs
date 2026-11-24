using System.Text.Json;
using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode;

/// <summary>Payload a hook CLI reads from stdin. Optional members are init properties so new fields can be added without breaking callers.</summary>
public sealed record HookInput
{
    public string SessionId { get; init; } = string.Empty;
    public string? Prompt { get; init; }
    public string? ToolName { get; init; }
    public JsonElement? ToolInput { get; init; }
    public JsonElement? ToolResponse { get; init; }

    /// <summary>The permission mode Claude Code reports, such as <c>default</c> or <c>dontAsk</c>; <see langword="null"/>
    /// when the payload has none. It is how a run that cannot ask is recognised.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PermissionMode { get; init; }
}
