using System.Text.Json;

namespace AI.Sentinel.Copilot;

/// <summary>Reads the text the model receives from a Copilot tool result, shaped <c>{resultType, textResultForLlm}</c>,
/// or <c>{result_type, text_result_for_llm}</c> in the VS Code compatible payload.</summary>
internal static class CopilotToolResult
{
    /// <summary>The <c>textResultForLlm</c> or <c>text_result_for_llm</c> string of <paramref name="result"/>;
    /// <see langword="null"/> when the result is not an object holding one.</summary>
    internal static string? TextForLlm(JsonElement result)
    {
        if (result.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (result.TryGetProperty("textResultForLlm", out var text) && text.ValueKind == JsonValueKind.String)
        {
            return text.GetString();
        }

        return result.TryGetProperty("text_result_for_llm", out var snake) && snake.ValueKind == JsonValueKind.String
            ? snake.GetString()
            : null;
    }
}
