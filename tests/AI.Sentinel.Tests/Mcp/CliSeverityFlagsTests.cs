using Xunit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp.Cli;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")] // env var sets
public class CliSeverityFlagsTests
{
    [Fact]
    public void CliFlag_OverridesEnvVar()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", "Warn");
        try
        {
            var resolved = SeverityFlagParser.Parse(
                args: new[] { "--on-critical", "Block" },
                envVar: "SENTINEL_MCP_ON_CRITICAL",
                fallback: HookDecision.Warn);
            Assert.Equal(HookDecision.Block, resolved);
        }
        finally { Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", null); }
    }

    [Fact]
    public void NoCliFlag_FallsBackToEnvVar()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", "Block");
        try
        {
            var resolved = SeverityFlagParser.Parse(
                args: Array.Empty<string>(),
                envVar: "SENTINEL_MCP_ON_CRITICAL",
                fallback: HookDecision.Warn);
            Assert.Equal(HookDecision.Block, resolved);
        }
        finally { Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", null); }
    }

    [Fact]
    public void NoCliFlag_NoEnvVar_ReturnsFallback()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", null);
        var resolved = SeverityFlagParser.Parse(
            args: Array.Empty<string>(),
            envVar: "SENTINEL_MCP_ON_CRITICAL",
            fallback: HookDecision.Warn);
        Assert.Equal(HookDecision.Warn, resolved);
    }

    [Fact]
    public void CliFlag_CaseInsensitive()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", null);
        var resolved = SeverityFlagParser.Parse(
            args: new[] { "--on-critical", "block" },
            envVar: "SENTINEL_MCP_ON_CRITICAL",
            fallback: HookDecision.Warn);
        Assert.Equal(HookDecision.Block, resolved);
    }

    [Fact]
    public void CliFlag_InvalidValue_FallsBackToEnvVar()
    {
        // Garbage CLI value should fall back to env (or fallback). Don't crash.
        Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", "Block");
        try
        {
            var resolved = SeverityFlagParser.Parse(
                args: new[] { "--on-critical", "Banana" },
                envVar: "SENTINEL_MCP_ON_CRITICAL",
                fallback: HookDecision.Warn);
            Assert.Equal(HookDecision.Block, resolved); // fell back to env, didn't crash
        }
        finally { Environment.SetEnvironmentVariable("SENTINEL_MCP_ON_CRITICAL", null); }
    }
}
