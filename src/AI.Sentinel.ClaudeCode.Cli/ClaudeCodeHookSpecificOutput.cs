using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Cli;

/// <summary>The <c>hookSpecificOutput</c> object of <see cref="ClaudeCodeWireOutput"/>.</summary>
internal sealed record ClaudeCodeHookSpecificOutput
{
    /// <summary>The event the output answers, such as <c>PostToolUse</c>; Claude Code requires it.</summary>
    public required string HookEventName { get; init; }

    /// <summary>Replaces the tool's output before Claude sees it.</summary>
    public JsonElement? UpdatedToolOutput { get; init; }

    /// <summary>Text added for Claude next to the tool result.</summary>
    public string? AdditionalContext { get; init; }
}
