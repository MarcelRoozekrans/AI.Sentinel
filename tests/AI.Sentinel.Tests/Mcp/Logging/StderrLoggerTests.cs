using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
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

    [Fact]
    public void Format_NDJSON_EscapesJsonSpecialCharsInValues()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", "1");
        try
        {
            const string nasty = "she said \"hi\" and \\path\nnext";
            var line = StderrLogger.Format(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["field"] = nasty,
            });

            // The output must be parseable JSON — proves quotes/backslashes/control chars
            // are escaped rather than written raw.
            using var doc = JsonDocument.Parse(line);
            var roundTripped = doc.RootElement.GetProperty("field").GetString();
            Assert.Equal(nasty, roundTripped);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        }
    }

    [Fact]
    public void Format_KeyValue_PreservesEqualsInValues()
    {
        // Document the actual behavior: key=value format is unstructured text — values
        // containing '=' (e.g. base64 padding in Authorization headers) are appended as-is
        // with no quoting or escaping. A naive parser splitting on the first '=' still
        // recovers the original value.
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        var line = StderrLogger.Format(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Authorization"] = "Basic abc==",
        });
        Assert.Equal("Authorization=Basic abc==", line);
    }

    [Fact]
    public void Log_WritesToStderr()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        var prev = Console.Error;
        var sw = new StringWriter();
        Console.SetError(sw);
        try
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "tools_call",
                ["tool"]  = "Bash",
            });
        }
        finally
        {
            Console.SetError(prev);
        }

        var written = sw.ToString();
        Assert.Equal("event=tools_call tool=Bash" + Environment.NewLine, written);
    }
}
