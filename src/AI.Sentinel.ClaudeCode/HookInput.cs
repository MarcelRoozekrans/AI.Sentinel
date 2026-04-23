using System.Text.Json;

namespace AI.Sentinel.ClaudeCode;

public sealed record HookInput(
    string SessionId,
    string? Prompt,
    string? ToolName,
    JsonElement? ToolInput,
    JsonElement? ToolResponse);
