namespace AI.Sentinel.Audit;

/// <summary>
/// Well-known values for <see cref="AuditEntry.Source"/>, naming the tool that wrote an entry.
/// In-process applications leave <see cref="AuditEntry.Source"/> <see langword="null"/>.
/// </summary>
public static class AuditSources
{
    /// <summary>Written by the Claude Code hook CLI.</summary>
    public const string ClaudeCode = "claude-code";

    /// <summary>Written by the GitHub Copilot hook CLI.</summary>
    public const string Copilot = "copilot";

    /// <summary>Written by the MCP proxy.</summary>
    public const string Mcp = "mcp";
}
