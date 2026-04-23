namespace AI.Sentinel.Mcp;

/// <summary>Describes the target MCP server that the proxy spawns as a subprocess.</summary>
/// <param name="Command">Executable to launch (e.g., <c>uvx</c>, <c>npx</c>).</param>
/// <param name="Args">Arguments passed to the command.</param>
public sealed record ProxyTargetSpec(string Command, IReadOnlyList<string> Args);
