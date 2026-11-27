using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Codex.Cli;

/// <summary>
/// The JSON <c>sentinel-codex-hook</c> writes to stdout, in the shape Codex documents for hook output
/// (https://developers.openai.com/codex/hooks). <see cref="HookOutput"/> stays the adapter's result; this maps it per
/// event.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Allow is <c>{}</c>.</item>
/// <item>Warn is <c>{"systemMessage":"AI.Sentinel: reason"}</c>, which Codex shows as a warning.</item>
/// <item>Block on UserPromptSubmit or PreToolUse writes nothing: exit code 2 and the reason on stderr carry it.</item>
/// <item>Block on PostToolUse is <c>decision: "block"</c> with the reason: Codex replaces the tool result with that
/// feedback. The tool already ran, so that is all a block can do there.</item>
/// </list>
/// Codex cannot ask on a PreToolUse: <c>permissionDecision: "ask"</c> is parsed but unsupported, and the call then
/// continues. An ask outcome is therefore settled into a deny with instructions, see <see cref="Resolve"/>. Deny, allow
/// and defer map as for the other hooks, and guidance is <c>additionalContext</c> for the model, which all three
/// events accept. Codex cannot replace a tool result either, so a redacted result is never written.
/// </remarks>
internal sealed record CodexWireOutput
{
    /// <summary><c>block</c> on a PostToolUse block; otherwise absent.</summary>
    public string? Decision { get; init; }

    /// <summary>The block reason, with <see cref="Decision"/>.</summary>
    public string? Reason { get; init; }

    /// <summary>A warning shown to the user.</summary>
    public string? SystemMessage { get; init; }

    /// <summary>The event-specific output: the context added for the model.</summary>
    public CodexHookSpecificOutput? HookSpecificOutput { get; init; }

    private static string EventName(HookEvent evt) => evt switch
    {
        HookEvent.PreToolUse => "PreToolUse",
        HookEvent.PostToolUse => "PostToolUse",
        _ => "UserPromptSubmit",
    };

    /// <summary>Settles an ask into a deny with instructions, because Codex has no way to ask from a hook. Anything
    /// else is returned as it is.</summary>
    public static HookOutput Resolve(HookOutput output)
    {
        ArgumentNullException.ThrowIfNull(output);
        return output.Outcome is { Outcome: DecisionOutcome.Ask } ask
            ? ask.ToHookOutput(canAsk: false) with { UpdatedToolOutput = output.UpdatedToolOutput, Redactions = output.Redactions }
            : output;
    }

    /// <summary>Maps <paramref name="output"/> for <paramref name="evt"/>; null when nothing is written to stdout.</summary>
    public static CodexWireOutput? From(HookEvent evt, HookOutput output)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (output.Outcome is { Outcome: DecisionOutcome.Guidance } && output.Decision != HookDecision.Block)
        {
            return new CodexWireOutput
            {
                HookSpecificOutput = new CodexHookSpecificOutput
                {
                    HookEventName = EventName(evt),
                    AdditionalContext = output.Reason ?? string.Empty,
                },
            };
        }

        if (output.Decision == HookDecision.Block)
        {
            return evt == HookEvent.PostToolUse ? new CodexWireOutput { Decision = "block", Reason = output.Reason } : null;
        }

        return new CodexWireOutput
        {
            SystemMessage = output.Decision == HookDecision.Warn ? "AI.Sentinel: " + output.Reason : null,
        };
    }
}
