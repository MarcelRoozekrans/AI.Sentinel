using System.Text;
using System.Text.Json;
using AI.Sentinel.Approvals.Conditions;

namespace AI.Sentinel.Approvals.Semantic;

/// <summary>Picks the texts of a tool call that a semantic approval scores.</summary>
internal static class SemanticApprovalText
{
    private const string Root = "$";
    private const string CommandPath = "$.command";

    // Tool names match ordinally: Claude Code's "Bash" and Copilot's "bash" are separate. Copilot passes the
    // shell command as "command" in toolArgs, as for Bash.
    private static readonly ArgumentPath[] CommandPaths = [ArgumentPath.Parse(CommandPath)];

    public static IReadOnlyList<ScoredText> Select(string toolName, JsonElement args, IReadOnlyList<ArgumentPath>? paths, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(toolName);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBytes);

        var result = new List<ScoredText>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(string path, string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return;
            var cut = Truncate(text, maxBytes, out var truncated);
            if (string.IsNullOrWhiteSpace(cut) || !seen.Add(cut))
                return;
            result.Add(new ScoredText(path, cut, truncated));
        }

        if (args.ValueKind == JsonValueKind.Undefined)
            return result;

        if (args.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array))
        {
            if (ValueText(args) is { } raw)
                Add(Root, raw);
            return result;
        }

        var effective = paths ?? (toolName is "Bash" or "bash" or "powershell" ? CommandPaths : null);
        if (effective is null)
        {
            if (ArgumentPath.TryWriteCompact(args, out var compact))
                Add(Root, compact);
            return result;
        }

        foreach (var path in effective)
            if (path.Resolve(args, out var text) == ArgumentPathResult.Resolved)
                Add(path.Text, text);
        return result;
    }

    private static string? ValueText(JsonElement value)
    {
        try
        {
            return value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => value.GetRawText(),
                _ => null,
            };
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Cuts to at most <paramref name="maxBytes"/> UTF-8 bytes without splitting a surrogate pair.</summary>
    private static string Truncate(string text, int maxBytes, out bool truncated)
    {
        truncated = false;
        // Every char is at most 3 UTF-8 bytes, so a short string cannot exceed the cap.
        if (text.Length <= maxBytes / 3)
            return text;

        var bytes = 0;
        var i = 0;
        while (i < text.Length)
        {
            var size = 1;
            var units = 1;
            var c = text[i];
            if (c >= 0x800)
            {
                if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                {
                    size = 4;
                    units = 2;
                }
                else
                {
                    size = 3;
                }
            }
            else if (c >= 0x80)
            {
                size = 2;
            }

            if (bytes + size > maxBytes)
            {
                truncated = true;
                return text.Substring(0, i);
            }

            bytes += size;
            i += units;
        }

        return text;
    }
}
