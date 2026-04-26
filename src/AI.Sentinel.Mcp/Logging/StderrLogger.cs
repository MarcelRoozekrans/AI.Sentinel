using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.Mcp.Logging;

/// <summary>
/// Centralised stderr logger for the MCP proxy. Supports key=value (default)
/// and NDJSON output (opt-in via <c>SENTINEL_MCP_LOG_JSON=1</c>).
/// </summary>
internal static class StderrLogger
{
    private static bool UseJson => string.Equals(
        Environment.GetEnvironmentVariable("SENTINEL_MCP_LOG_JSON"),
        "1",
        StringComparison.Ordinal);

    /// <summary>Builds the stderr line for the supplied fields. Public for testing.</summary>
    public static string Format(IReadOnlyDictionary<string, string> fields)
    {
        if (UseJson)
        {
            return JsonSerializer.Serialize(
                fields,
                McpJsonContext.Default.IReadOnlyDictionaryStringString);
        }

        var sb = new StringBuilder();
        var first = true;
        foreach (var kvp in fields)
        {
            if (!first)
            {
                sb.Append(' ');
            }

            sb.Append(kvp.Key).Append('=').Append(kvp.Value);
            first = false;
        }

        return sb.ToString();
    }

    /// <summary>Writes a stderr log line in the configured format.</summary>
    public static void Log(IReadOnlyDictionary<string, string> fields)
        => Console.Error.WriteLine(Format(fields));
}
