namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>The shared kind of a tool call (ADR-235): one policy rule covers the same kind of tool in every CLI.</summary>
internal enum ToolKind
{
    Other = 0,
    Shell,
    Read,
    Search,
    Write,
    Edit,
    Fetch,
    Mcp,
    Agent,
}
