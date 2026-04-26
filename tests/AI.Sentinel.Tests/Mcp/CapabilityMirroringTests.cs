using System.IO.Pipelines;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")]
public class CapabilityMirroringTests
{
    private static HookConfig DefaultConfig() => new(
        OnCritical: HookDecision.Block,
        OnHigh:     HookDecision.Block,
        OnMedium:   HookDecision.Block,
        OnLow:      HookDecision.Block,
        Verbose:    false);

    [Fact]
    public async Task PromptsOnlyTarget_AdvertisesPromptsOnly()
    {
        await using var h = await StartHarnessAsync(new ServerCapabilities
        {
            Prompts = new PromptsCapability(),
        });

        var caps = h.DriverClient.ServerCapabilities;
        Assert.NotNull(caps.Prompts);
        Assert.Null(caps.Tools);
        Assert.Null(caps.Resources);
    }

    [Fact]
    public async Task FullTarget_AdvertisesAll()
    {
        await using var h = await StartHarnessAsync(new ServerCapabilities
        {
            Tools     = new ToolsCapability(),
            Prompts   = new PromptsCapability(),
            Resources = new ResourcesCapability(),
        });

        var caps = h.DriverClient.ServerCapabilities;
        Assert.NotNull(caps.Tools);
        Assert.NotNull(caps.Prompts);
        Assert.NotNull(caps.Resources);
    }

    [Fact]
    public async Task ToolsOnlyTarget_AdvertisesToolsOnly_NoResources()
    {
        await using var h = await StartHarnessAsync(new ServerCapabilities
        {
            Tools = new ToolsCapability(),
        });

        var caps = h.DriverClient.ServerCapabilities;
        Assert.NotNull(caps.Tools);
        Assert.Null(caps.Prompts);
        Assert.Null(caps.Resources);
    }

    private sealed record ProxyHarness(
        FakeMcpServer Fake,
        McpClient DriverClient,
        Task RunTask,
        CancellationTokenSource Cts) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Cts.CancelAsync().ConfigureAwait(false);
            try { await RunTask.ConfigureAwait(false); } catch (OperationCanceledException) { }
            await DriverClient.DisposeAsync().ConfigureAwait(false);
            await Fake.DisposeAsync().ConfigureAwait(false);
            Cts.Dispose();
        }
    }

    private static async Task<ProxyHarness> StartHarnessAsync(ServerCapabilities targetCaps)
    {
        var fake = new FakeMcpServer { AdvertisedCapabilities = targetCaps };
        var targetTransport = fake.Start();
        var hostToProxy = new Pipe();
        var proxyToHost = new Pipe();

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var runTask = McpProxy.RunAsync(
            hostTransport: new StreamServerTransport(
                inputStream: hostToProxy.Reader.AsStream(),
                outputStream: proxyToHost.Writer.AsStream(),
                serverName: "proxy-server",
                loggerFactory: NullLoggerFactory.Instance),
            targetTransport: targetTransport,
            config: DefaultConfig(),
            preset: McpDetectorPreset.Security,
            maxScanBytes: 262144,
            stderr: TextWriter.Null,
            ct: cts.Token,
            embeddingGenerator: new FakeEmbeddingGenerator());

        var driverClient = await McpClient.CreateAsync(
            clientTransport: new StreamClientTransport(
                serverInput: hostToProxy.Writer.AsStream(),
                serverOutput: proxyToHost.Reader.AsStream(),
                loggerFactory: NullLoggerFactory.Instance),
            clientOptions: null,
            loggerFactory: NullLoggerFactory.Instance,
            cancellationToken: cts.Token);

        return new ProxyHarness(fake, driverClient, runTask, cts);
    }
}
