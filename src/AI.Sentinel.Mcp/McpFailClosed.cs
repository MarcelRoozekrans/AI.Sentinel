using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace AI.Sentinel.Mcp;

/// <summary>
/// The block the MCP proxy raises when the detection pipeline itself throws (#544). A scan that could not run
/// must not let the message through, the same rule the Claude Code hooks follow (#478). The message names the
/// exception type only, so nothing from the failing scan, such as a secret in its text, reaches the peer.
/// </summary>
internal static class McpFailClosed
{
    internal const string Prefix = "Blocked by AI.Sentinel: internal error";

    internal static McpProtocolException Block(Exception ex)
    {
        ArgumentNullException.ThrowIfNull(ex);
        return new McpProtocolException($"{Prefix} ({ex.GetType().Name})", McpErrorCode.InternalError);
    }
}
