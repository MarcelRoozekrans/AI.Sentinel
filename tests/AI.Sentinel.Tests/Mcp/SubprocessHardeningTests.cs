using System;
using System.Diagnostics;
using System.Threading.Tasks;
using AI.Sentinel.Mcp;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")] // env var sets
public class SubprocessHardeningTests
{
    [Fact]
    public void DefaultGrace_IsFiveSeconds()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", null);
        Assert.Equal(TimeSpan.FromSeconds(5), McpProxy.GetShutdownGrace());
    }

    [Fact]
    public void EnvVar_PositiveInteger_OverridesDefault()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", "30");
        try
        {
            Assert.Equal(TimeSpan.FromSeconds(30), McpProxy.GetShutdownGrace());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", null);
        }
    }

    [Fact]
    public void EnvVar_Garbage_FallsBackToDefault()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", "not-a-number");
        try
        {
            Assert.Equal(TimeSpan.FromSeconds(5), McpProxy.GetShutdownGrace());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", null);
        }
    }

    [Fact]
    public void EnvVar_NegativeOrZero_FallsBackToDefault()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", "-1");
        try
        {
            Assert.Equal(TimeSpan.FromSeconds(5), McpProxy.GetShutdownGrace());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", null);
        }

        Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", "0");
        try
        {
            Assert.Equal(TimeSpan.FromSeconds(5), McpProxy.GetShutdownGrace());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC", null);
        }
    }

    [Fact]
    public async Task DisposeWithGrace_FastTransport_CompletesNormally()
    {
        var transport = new FastDisposeTransport();
        var sw = Stopwatch.StartNew();
        await McpProxy.DisposeWithGraceAsync(transport, TimeSpan.FromSeconds(5));
        sw.Stop();
        Assert.True(transport.Disposed);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"Expected fast disposal, took {sw.Elapsed}");
    }

    [Fact]
    public async Task DisposeWithGrace_HungTransport_GivesUpAfterGrace()
    {
        var transport = new HungDisposeTransport();
        var sw = Stopwatch.StartNew();
        await McpProxy.DisposeWithGraceAsync(transport, TimeSpan.FromMilliseconds(200));
        sw.Stop();
        Assert.False(transport.Disposed); // never completed
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2),
            $"Should have given up after grace; took {sw.Elapsed}");
    }

    private sealed class FastDisposeTransport : IAsyncDisposable
    {
        public bool Disposed { get; private set; }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class HungDisposeTransport : IAsyncDisposable
    {
        public bool Disposed { get; private set; }

        public async ValueTask DisposeAsync()
        {
            await Task.Delay(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            Disposed = true;
        }
    }
}
