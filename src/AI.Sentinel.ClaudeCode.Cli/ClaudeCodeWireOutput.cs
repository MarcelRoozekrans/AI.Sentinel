using System.Globalization;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Cli;

/// <summary>
/// The JSON <c>sentinel-hook</c> writes to stdout, in the shape Claude Code documents for hook output
/// (https://code.claude.com/docs/en/hooks). <see cref="HookOutput"/> stays the adapter's result; this maps it per
/// event.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Allow is <c>{}</c>.</item>
/// <item>Warn is <c>{"systemMessage":"AI.Sentinel: reason"}</c>, which the user sees.</item>
/// <item>Block on UserPromptSubmit or PreToolUse writes nothing: exit code 2 and the reason on stderr carry it.</item>
/// <item>On PostToolUse a replaced tool output goes in <c>hookSpecificOutput.updatedToolOutput</c>. A redaction adds
/// <c>additionalContext</c> naming the redacted types, and a Block adds <c>decision: "block"</c> with the reason, which
/// is repeated as <c>additionalContext</c> so Claude keeps it when the host rejects the replacement.</item>
/// </list>
/// A decision that carries an outcome (<see cref="HookOutput.Outcome"/>) is written as ADR-234 says: deny as a Block,
/// allow and defer as Allow, so no permission decision is emitted and the CLI's own prompt applies, ask as
/// <c>permissionDecision: "ask"</c> on PreToolUse, and guidance as <c>additionalContext</c> for the agent. A decision
/// from a severity action alone keeps the output above.
/// </remarks>
internal sealed record ClaudeCodeWireOutput
{
    /// <summary><c>block</c> on a PostToolUse block; otherwise absent.</summary>
    public string? Decision { get; init; }

    /// <summary>The block reason, with <see cref="Decision"/>.</summary>
    public string? Reason { get; init; }

    /// <summary>A warning shown to the user.</summary>
    public string? SystemMessage { get; init; }

    /// <summary>The event-specific output: the replaced tool output and the context added for Claude.</summary>
    public ClaudeCodeHookSpecificOutput? HookSpecificOutput { get; init; }

    private const string PostToolUseEventName = "PostToolUse";
    private const string PreToolUseEventName = "PreToolUse";
    private const string UserPromptSubmitEventName = "UserPromptSubmit";

    private static string EventName(HookEvent evt) => evt switch
    {
        HookEvent.PreToolUse => PreToolUseEventName,
        HookEvent.PostToolUse => PostToolUseEventName,
        _ => UserPromptSubmitEventName,
    };

    /// <summary>True when Claude Code can ask the developer for this call: only a PreToolUse, and only when the run is
    /// not headless.</summary>
    public static bool CanAsk(HookEvent evt, bool headless) => evt == HookEvent.PreToolUse && !headless;

    /// <summary>Claude Code's hook payload has no headless flag, so a run that cannot ask is recognised by the
    /// <c>dontAsk</c> permission mode, which never prompts, or by the operator setting <c>SENTINEL_HOOK_HEADLESS</c>.</summary>
    public static bool IsHeadless(HookInput input, HookConfig config)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(config);
        return config.Headless || string.Equals(input.PermissionMode, "dontAsk", StringComparison.Ordinal);
    }

    /// <summary>Settles an ask that Claude Code cannot express here into a deny with instructions; anything else is
    /// returned as it is.</summary>
    public static HookOutput Resolve(HookOutput output, HookEvent evt, bool headless)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (output.Outcome is not { Outcome: DecisionOutcome.Ask } ask || CanAsk(evt, headless))
        {
            return output;
        }

        return ask.ToHookOutput(canAsk: false) with { UpdatedToolOutput = output.UpdatedToolOutput, Redactions = output.Redactions };
    }

    /// <summary>Ask and guidance, which have an output of their own.</summary>
    private static ClaudeCodeWireOutput FromOutcome(HookEvent evt, HookOutput output, DecisionOutcome outcome)
    {
        var reason = output.Reason ?? string.Empty;
        var context = output.Redactions is { Count: > 0 } redactions && evt == HookEvent.PostToolUse && output.UpdatedToolOutput is not null
            ? reason + "\n" + RedactedContext(redactions)
            : reason;
        return new ClaudeCodeWireOutput
        {
            HookSpecificOutput = new ClaudeCodeHookSpecificOutput
            {
                HookEventName = EventName(evt),
                UpdatedToolOutput = evt == HookEvent.PostToolUse ? output.UpdatedToolOutput : null,
                AdditionalContext = outcome == DecisionOutcome.Guidance ? context : null,
                PermissionDecision = outcome == DecisionOutcome.Ask ? "ask" : null,
                PermissionDecisionReason = outcome == DecisionOutcome.Ask ? reason : null,
            },
        };
    }

    /// <summary>Maps <paramref name="output"/> for <paramref name="evt"/>; null when nothing is written to stdout.</summary>
    public static ClaudeCodeWireOutput? From(HookEvent evt, HookOutput output)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (output.Outcome is { Outcome: DecisionOutcome.Ask or DecisionOutcome.Guidance } carried
            && output.Decision != HookDecision.Block)
        {
            return FromOutcome(evt, output, carried.Outcome);
        }

        if (output.Decision == HookDecision.Block)
        {
            if (evt != HookEvent.PostToolUse)
            {
                return null;
            }

            // The tool already ran, so a block can only withhold its output and tell Claude why.
            return new ClaudeCodeWireOutput
            {
                Decision = "block",
                Reason = output.Reason,
                HookSpecificOutput = output.UpdatedToolOutput is { } withheld
                    ? new ClaudeCodeHookSpecificOutput
                    {
                        HookEventName = PostToolUseEventName,
                        UpdatedToolOutput = withheld,
                        AdditionalContext = output.Reason,
                    }
                    : null,
            };
        }

        return new ClaudeCodeWireOutput
        {
            SystemMessage = output.Decision == HookDecision.Warn ? "AI.Sentinel: " + output.Reason : null,
            HookSpecificOutput = evt == HookEvent.PostToolUse && output.UpdatedToolOutput is { } updated
                ? new ClaudeCodeHookSpecificOutput
                {
                    HookEventName = PostToolUseEventName,
                    UpdatedToolOutput = updated,
                    AdditionalContext = output.Redactions is { Count: > 0 } redactions ? RedactedContext(redactions) : null,
                }
                : null,
        };
    }

    /// <summary>
    /// <c>AI.Sentinel redacted 1 API_KEY, 1 EMAIL in this tool output. Placeholders such as [API_KEY_n_tag],
    /// [EMAIL_n_tag] stand for ...</c>: counts and one example shape per type, types in ordinal order. It names types
    /// only, never a value or a real placeholder. It also helps when Claude Code rejects a built-in tool's rewritten
    /// output and the model sees the original.
    /// </summary>
    private static string RedactedContext(IReadOnlyDictionary<string, int> redactions)
    {
        var types = new List<string>(redactions.Keys);
        types.Sort(StringComparer.Ordinal);
        var sb = new StringBuilder("AI.Sentinel redacted ");
        for (var i = 0; i < types.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }

            sb.Append(redactions[types[i]].ToString(CultureInfo.InvariantCulture)).Append(' ').Append(types[i]);
        }

        sb.Append(" in this tool output. Placeholders such as ");
        for (var i = 0; i < types.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }

            sb.Append('[').Append(types[i]).Append("_n_tag]");
        }

        sb.Append(" stand for the real values; do not write them to files or commands.");
        return sb.ToString();
    }
}
