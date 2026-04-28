using System;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using AI.Sentinel.Mcp.Logging;

namespace AI.Sentinel.Benchmarks;

/// <summary>
/// Microbenchmarks for <see cref="StderrLogger.Format"/> — runs a few times per MCP request.
/// Compares the default key=value formatter against the NDJSON path
/// (<c>SENTINEL_MCP_LOG_JSON=1</c>) for both small (3-field) and large (20-field) payloads.
/// </summary>
/// <remarks>
/// Toggling the env var inside each benchmark is unusual — but <c>StderrLogger.UseJson</c>
/// reads it on every call, and that env-var read is itself part of the production cost.
/// </remarks>
[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("Mcp")]
public class McpLoggingBenchmarks
{
    private Dictionary<string, string> _smallDict = null!;
    private Dictionary<string, string> _largeDict = null!;

    [GlobalSetup]
    public void Setup()
    {
        _smallDict = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]  = "tools_call",
            ["tool"]   = "Bash",
            ["action"] = "scanned",
        };

        _largeDict = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < 20; i++)
        {
            _largeDict[$"field{i}"] = $"value{i}";
        }
    }

    [Benchmark(Baseline = true, Description = "Small dict (3 fields) / key=value")]
    public string Small_KeyValue()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        return StderrLogger.Format(_smallDict);
    }

    [Benchmark(Description = "Small dict (3 fields) / NDJSON")]
    public string Small_NDJSON()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", "1");
        return StderrLogger.Format(_smallDict);
    }

    [Benchmark(Description = "Large dict (20 fields) / key=value")]
    public string Large_KeyValue()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", null);
        return StderrLogger.Format(_largeDict);
    }

    [Benchmark(Description = "Large dict (20 fields) / NDJSON")]
    public string Large_NDJSON()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_LOG_JSON", "1");
        return StderrLogger.Format(_largeDict);
    }
}
