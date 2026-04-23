using System.Text.Json;

namespace AI.Sentinel.Copilot;

public sealed record CopilotHookInput(
    string SessionId,
    string? Prompt,
    string? ToolName,
    JsonElement? ToolInput,
    JsonElement? ToolResponse);
