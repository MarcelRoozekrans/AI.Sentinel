namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Details of an MCP tool call.</summary>
/// <param name="Server">The MCP server name.</param>
/// <param name="Endpoint">The server endpoint. Empty: no hook payload carries it.</param>
/// <param name="Tool">The tool name on that server.</param>
internal sealed record McpDetails(string Server, string Endpoint, string Tool);
