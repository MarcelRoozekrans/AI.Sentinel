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

    /// <summary>Maps <paramref name="output"/> for <paramref name="evt"/>; null when nothing is written to stdout.</summary>
    public static ClaudeCodeWireOutput? From(HookEvent evt, HookOutput output)
    {
        ArgumentNullException.ThrowIfNull(output);

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
    /// <c>AI.Sentinel redacted 1 API_KEY, 1 EMAIL in this tool output. ...</c>: counts per type, types in ordinal
    /// order. It names types only, never a value. It also helps when Claude Code rejects a built-in tool's rewritten
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

        sb.Append(" in this tool output. Placeholders such as [EMAIL_1_k3f9x2] stand for the real values; do not write them to files or commands.");
        return sb.ToString();
    }
}
