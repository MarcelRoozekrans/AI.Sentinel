using System.Collections.Frozen;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Maps the tool names of each CLI onto <see cref="ToolKind"/>. A tool the table does not know is <see cref="ToolKind.Other"/>.</summary>
internal static class ToolKinds
{
    private const string McpPrefix = "mcp__";

    private static readonly FrozenDictionary<string, ToolKind> ClaudeCode = new Dictionary<string, ToolKind>(StringComparer.Ordinal)
    {
        ["Bash"] = ToolKind.Shell,
        ["Read"] = ToolKind.Read,
        ["NotebookRead"] = ToolKind.Read,
        ["Glob"] = ToolKind.Search,
        ["Grep"] = ToolKind.Search,
        ["LS"] = ToolKind.Search,
        ["Write"] = ToolKind.Write,
        ["Edit"] = ToolKind.Edit,
        ["MultiEdit"] = ToolKind.Edit,
        ["NotebookEdit"] = ToolKind.Edit,
        ["WebFetch"] = ToolKind.Fetch,
        ["WebSearch"] = ToolKind.Fetch,
        ["Task"] = ToolKind.Agent,
        ["Agent"] = ToolKind.Agent,
    }.ToFrozenDictionary(StringComparer.Ordinal);

    // Copilot CLI tool names, as the placeholder guard and the hook tests know them.
    private static readonly FrozenDictionary<string, ToolKind> Copilot = new Dictionary<string, ToolKind>(StringComparer.Ordinal)
    {
        ["bash"] = ToolKind.Shell,
        ["powershell"] = ToolKind.Shell,
        ["view"] = ToolKind.Read,
        ["glob"] = ToolKind.Search,
        ["grep"] = ToolKind.Search,
        ["create"] = ToolKind.Write,
        ["edit"] = ToolKind.Edit,
        ["str_replace_editor"] = ToolKind.Edit,
        ["apply_patch"] = ToolKind.Edit,
        ["web_fetch"] = ToolKind.Fetch,
        ["task"] = ToolKind.Agent,
    }.ToFrozenDictionary(StringComparer.Ordinal);

    // Codex hook tool names. A file edit is always apply_patch: Edit and Write are matcher aliases only, and the hook
    // input still reports apply_patch. Reads, searches and fetches go through Bash or MCP tools, so they map to those.
    private static readonly FrozenDictionary<string, ToolKind> Codex = new Dictionary<string, ToolKind>(StringComparer.Ordinal)
    {
        ["Bash"] = ToolKind.Shell,
        ["apply_patch"] = ToolKind.Edit,
        ["spawn_agent"] = ToolKind.Agent,
        ["Agent"] = ToolKind.Agent,
    }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>The kind of <paramref name="toolName"/> in <paramref name="cli"/>. Names match ordinally.</summary>
    public static ToolKind Map(string cli, string? toolName)
    {
        if (string.IsNullOrEmpty(toolName))
        {
            return ToolKind.Other;
        }

        if (toolName.StartsWith(McpPrefix, StringComparison.Ordinal) && toolName.Length > McpPrefix.Length)
        {
            return string.Equals(cli, PolicyClis.ClaudeCode, StringComparison.Ordinal) || string.Equals(cli, PolicyClis.Copilot, StringComparison.Ordinal)
                || string.Equals(cli, PolicyClis.Codex, StringComparison.Ordinal)
                ? ToolKind.Mcp
                : ToolKind.Other;
        }

        if (string.Equals(cli, PolicyClis.ClaudeCode, StringComparison.Ordinal))
        {
            return ClaudeCode.GetValueOrDefault(toolName);
        }

        if (string.Equals(cli, PolicyClis.Copilot, StringComparison.Ordinal))
        {
            // A PascalCase hook event makes Copilot send the VS Code payload with Claude tool names.
            return Copilot.TryGetValue(toolName, out var kind) ? kind : ClaudeCode.GetValueOrDefault(toolName);
        }

        if (string.Equals(cli, PolicyClis.Codex, StringComparison.Ordinal))
        {
            return Codex.GetValueOrDefault(toolName);
        }

        return ToolKind.Other;
    }

    /// <summary>The lowercase name policy input carries.</summary>
    public static string ToWire(this ToolKind kind) => kind switch
    {
        ToolKind.Shell => "shell",
        ToolKind.Read => "read",
        ToolKind.Search => "search",
        ToolKind.Write => "write",
        ToolKind.Edit => "edit",
        ToolKind.Fetch => "fetch",
        ToolKind.Mcp => "mcp",
        ToolKind.Agent => "agent",
        _ => "other",
    };
}
