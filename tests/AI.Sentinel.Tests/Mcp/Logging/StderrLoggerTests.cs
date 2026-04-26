using System;
using System.Collections.Generic;
using AI.Sentinel.Mcp.Logging;
using Xunit;

namespace AI.Sentinel.Tests.Mcp.Logging;

[Collection("NonParallel")] // env var sets
public class StderrLoggerTests
{
    [Fact]
    public void Format_NoJsonEnv_ProducesKeyValueLine()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        var line = StderrLogger.Format(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]  = "tools_call",
            ["tool"]   = "Bash",
            ["action"] = "scanned",
        });
        Assert.Equal("event=tools_call tool=Bash action=scanned", line);
    }

    [Fact]
    public void Format_JsonEnvSet_ProducesNDJSONLine()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", "1");
        try
        {
            var line = StderrLogger.Format(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "tools_call",
                ["tool"]  = "Bash",
            });
            Assert.StartsWith("{", line, StringComparison.Ordinal);
            Assert.Contains("\"event\":\"tools_call\"", line, StringComparison.Ordinal);
            Assert.Contains("\"tool\":\"Bash\"", line, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        }
    }
}
