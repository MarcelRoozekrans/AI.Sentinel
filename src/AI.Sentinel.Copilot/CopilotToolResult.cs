using System.Text.Json;

namespace AI.Sentinel.Copilot;

/// <summary>Reads the text the model receives from a Copilot tool result, shaped <c>{resultType, textResultForLlm}</c>.</summary>
internal static class CopilotToolResult
{
    /// <summary>The <c>textResultForLlm</c> string of <paramref name="result"/>; <see langword="null"/> when the result
    /// is not an object holding one.</summary>
    internal static string? TextForLlm(JsonElement result) =>
        result.ValueKind == JsonValueKind.Object
        && result.TryGetProperty("textResultForLlm", out var text)
        && text.ValueKind == JsonValueKind.String
            ? text.GetString()
            : null;
}
