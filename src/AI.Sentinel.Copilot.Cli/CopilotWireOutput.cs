using System.Text.Json;
using System.Text.Json.Serialization;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Copilot.Cli;

/// <summary>
/// The JSON <c>sentinel-copilot-hook</c> writes to stdout. It keeps the legacy <c>{"decision":...,"reason":...}</c>
/// members and adds the output fields of the Copilot hooks reference
/// (https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference) when there is something to
/// replace.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>On postToolUse a replaced result goes in <c>modifiedResult</c>: the redacted result, or on a block the
/// withheld text. Its <c>resultType</c> is always <c>success</c>: the reference requires it, and <c>failure</c> would
/// route the result to postToolUseFailure. An original status other than <c>success</c> is kept as a prefix of the
/// text, such as <c>[failure] </c>, so the model still learns how the tool ended.</item>
/// <item>On userPromptTransformed a replaced prompt goes in <c>modifiedTransformedPrompt</c>. Experimental until a live
/// check with the Copilot CLI confirms command hooks honour it.</item>
/// </list>
/// Copilot parses stdout only on exit code 0.
/// </remarks>
internal sealed record CopilotWireOutput
{
    /// <summary>The hook decision, kept from the earlier output.</summary>
    public required HookDecision Decision { get; init; }

    /// <summary>The reason for a Warn or a Block; written as <c>null</c> otherwise, as before.</summary>
    public string? Reason { get; init; }

    /// <summary>The tool result the model receives instead of the original, on postToolUse.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CopilotModifiedResult? ModifiedResult { get; init; }

    /// <summary>The prompt the model receives instead of the transformed prompt, on userPromptTransformed.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ModifiedTransformedPrompt { get; init; }

    private const string SuccessResultType = "success";

    /// <summary>Maps <paramref name="result"/> for <paramref name="evt"/>. A rewrite is written for its own event only.</summary>
    public static CopilotWireOutput From(CopilotHookEvent evt, CopilotHookResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var output = result.Output;
        return new CopilotWireOutput
        {
            Decision = output.Decision,
            Reason = output.Reason,
            ModifiedResult = evt == CopilotHookEvent.PostToolUse && output.UpdatedToolOutput is { } updated
                && ResultText(updated) is { } text
                ? new CopilotModifiedResult(SuccessResultType, WithStatus(OriginalStatus(updated, result), text))
                : null,
            ModifiedTransformedPrompt = evt == CopilotHookEvent.UserPromptTransformed ? result.ModifiedTransformedPrompt : null,
        };
    }

    /// <summary>The status of the original result: the <c>resultType</c> of the redacted result, which redaction keeps,
    /// or, for the withheld text, the one the adapter read from the original.</summary>
    private static string? OriginalStatus(JsonElement updated, CopilotHookResult result) =>
        CopilotToolResult.ResultType(updated) ?? result.ToolResultType;

    /// <summary><paramref name="text"/>, prefixed with <c>[status] </c> when <paramref name="status"/> is not
    /// <c>success</c>.</summary>
    private static string WithStatus(string? status, string text) =>
        status is null || string.Equals(status, SuccessResultType, StringComparison.OrdinalIgnoreCase)
            ? text
            : $"[{status}] {text}";

    /// <summary>The text of a replaced result: <c>textResultForLlm</c> of a redacted result, or the string itself, which
    /// is the withheld case.</summary>
    private static string? ResultText(JsonElement updated) =>
        updated.ValueKind == JsonValueKind.String ? updated.GetString() : CopilotToolResult.TextForLlm(updated);
}
