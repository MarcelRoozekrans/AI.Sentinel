using System.Text.Json;

namespace AI.Sentinel.Copilot;

/// <summary>Payload a hook CLI reads from stdin. Optional members are init properties so new fields can be added without breaking callers.</summary>
public sealed record CopilotHookInput
{
    public string SessionId { get; init; } = string.Empty;
    public string? Prompt { get; init; }
    public string? ToolName { get; init; }
    public JsonElement? ToolInput { get; init; }
    public JsonElement? ToolResponse { get; init; }
}
