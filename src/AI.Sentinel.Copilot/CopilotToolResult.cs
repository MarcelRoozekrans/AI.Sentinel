using System.Text.Json;
using AI.Sentinel.ClaudeCode;

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

    /// <summary>The <c>resultType</c> or <c>result_type</c> string of <paramref name="result"/>, such as <c>success</c> or
    /// <c>failure</c>; <see langword="null"/> when the result is not an object holding one, or the value is not
    /// identifier-like, so free text cannot reach the model through it.</summary>
    internal static string? ResultType(JsonElement result)
    {
        if (result.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var value = result.TryGetProperty("resultType", out var type) && type.ValueKind == JsonValueKind.String
            ? type.GetString()
            : result.TryGetProperty("result_type", out var snake) && snake.ValueKind == JsonValueKind.String
                ? snake.GetString()
                : null;
        return HookPipelineRunner.IsDiscriminator(value) ? value : null;
    }
}
