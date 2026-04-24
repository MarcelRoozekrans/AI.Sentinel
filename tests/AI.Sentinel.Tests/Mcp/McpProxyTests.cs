using System.IO.Pipelines;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")]
public class McpProxyTests
{
    private static HookConfig DefaultConfig() => new(
        OnCritical: HookDecision.Block,
        OnHigh:     HookDecision.Block,
        OnMedium:   HookDecision.Block,
        OnLow:      HookDecision.Block,
        Verbose:    false);

    [Fact]
    public async Task ForwardsToolsList_FromProxyClient_ToFakeTarget()
    {
        await using var fake = new FakeMcpServer();
        var targetTransport = fake.Start();

        var hostToProxy = new Pipe();
        var proxyToHost = new Pipe();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var hostTransport = new StreamServerTransport(
            inputStream: hostToProxy.Reader.AsStream(),
            outputStream: proxyToHost.Writer.AsStream(),
            serverName: "proxy-server",
            loggerFactory: NullLoggerFactory.Instance);

        var runTask = McpProxy.RunAsync(
            hostTransport: hostTransport,
            targetTransport: targetTransport,
            config: DefaultConfig(),
            preset: McpDetectorPreset.Security,
            maxScanBytes: 262144,
            ct: cts.Token);

        IClientTransport driverTransport = new StreamClientTransport(
            serverInput: hostToProxy.Writer.AsStream(),
            serverOutput: proxyToHost.Reader.AsStream(),
            loggerFactory: NullLoggerFactory.Instance);

        await using var driverClient = await McpClient.CreateAsync(
            clientTransport: driverTransport,
            clientOptions: null,
            loggerFactory: NullLoggerFactory.Instance,
            cancellationToken: cts.Token);

        var tools = await driverClient.ListToolsAsync(cancellationToken: cts.Token);

        Assert.Contains(tools, t => string.Equals(t.Name, "read_file", StringComparison.Ordinal));
        Assert.Contains(tools, t => string.Equals(t.Name, "write_file", StringComparison.Ordinal));

        await cts.CancelAsync();
        try { await runTask; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task ForwardsCleanToolCall_ToFakeTarget()
    {
        await using var fake = new FakeMcpServer();
        var targetTransport = fake.Start();

        var hostToProxy = new Pipe();
        var proxyToHost = new Pipe();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var hostTransport = new StreamServerTransport(
            inputStream: hostToProxy.Reader.AsStream(),
            outputStream: proxyToHost.Writer.AsStream(),
            serverName: "proxy-server",
            loggerFactory: NullLoggerFactory.Instance);

        var runTask = McpProxy.RunAsync(
            hostTransport: hostTransport,
            targetTransport: targetTransport,
            config: DefaultConfig(),
            preset: McpDetectorPreset.Security,
            maxScanBytes: 262144,
            ct: cts.Token);

        IClientTransport driverTransport = new StreamClientTransport(
            serverInput: hostToProxy.Writer.AsStream(),
            serverOutput: proxyToHost.Reader.AsStream(),
            loggerFactory: NullLoggerFactory.Instance);

        await using var driverClient = await McpClient.CreateAsync(
            clientTransport: driverTransport,
            clientOptions: null,
            loggerFactory: NullLoggerFactory.Instance,
            cancellationToken: cts.Token);

        var result = await driverClient.CallToolAsync(
            toolName: "read_file",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["path"] = "/tmp/hello.txt",
            },
            cancellationToken: cts.Token);

        Assert.Single(fake.ReceivedToolCalls);
        Assert.Equal("read_file", fake.ReceivedToolCalls[0].Name);
        Assert.NotNull(result);

        await cts.CancelAsync();
        try { await runTask; } catch (OperationCanceledException) { }
    }
}
