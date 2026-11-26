namespace AI.Sentinel.Codex.Cli;

/// <summary>The <c>hookSpecificOutput</c> object of <see cref="CodexWireOutput"/>.</summary>
internal sealed record CodexHookSpecificOutput
{
    /// <summary>The event the output answers, such as <c>PreToolUse</c>; Codex requires it.</summary>
    public required string HookEventName { get; init; }

    /// <summary>Text Codex adds for the model as developer context.</summary>
    public string? AdditionalContext { get; init; }
}
