using System.Collections.Frozen;
using System.Text.Json;
using AI.Sentinel.Detection;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Denies a write or shell tool call whose input holds a redaction placeholder. A model that read a redacted tool
/// result may copy the placeholder into a file or a command; the real value is gone, so the call would write the
/// placeholder in its place. Tool names match ordinally, the way each host spells them.
/// </summary>
internal static class PlaceholderGuard
{
    /// <summary>Claude Code tools that write files or run commands.</summary>
    public static readonly FrozenSet<string> ClaudeCodeTools =
        FrozenSet.ToFrozenSet(["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"], StringComparer.Ordinal);

    /// <summary>Copilot tools that write files, run commands or send input to a running shell, as the Copilot CLI
    /// hooks and command references name them.</summary>
    public static readonly FrozenSet<string> CopilotTools =
        FrozenSet.ToFrozenSet(
            ["create", "edit", "str_replace_editor", "apply_patch", "bash", "powershell", "write_bash", "write_powershell"],
            StringComparer.Ordinal);

    /// <summary>Fixed copy: it never echoes the placeholder or any other part of the input.</summary>
    public const string Reason = "AI.Sentinel denied this call: its input contains a redaction placeholder such as [EMAIL_1_k3f9x2]. The real value was redacted and must not be written to a file or a command. Ask the user for the value if you need it.";

    /// <summary>A Block when <paramref name="toolName"/> is in <paramref name="guardedTools"/> and a string anywhere in
    /// <paramref name="toolInput"/>, the root included, holds a placeholder; otherwise <see langword="null"/>. An absent
    /// input is <c>default</c>, whose kind is <see cref="JsonValueKind.Undefined"/>: it holds no string, so it passes.</summary>
    public static HookOutput? Check(string? toolName, JsonElement toolInput, FrozenSet<string> guardedTools)
    {
        ArgumentNullException.ThrowIfNull(guardedTools);
        if (toolName is null || !guardedTools.Contains(toolName))
        {
            return null;
        }

        return HasPlaceholder(toolInput) ? new HookOutput { Decision = HookDecision.Block, Reason = Reason } : null;
    }

    private static bool HasPlaceholder(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return element.GetString() is { } text && PlaceholderFormat.Pattern().IsMatch(text);
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (HasPlaceholder(property.Value)) return true;
                }
                return false;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (HasPlaceholder(item)) return true;
                }
                return false;
            default:
                return false;
        }
    }
}
