using System.IO.Pipelines;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")] // sets env vars + redirects Console.Error
public class ResourceReadInterceptorTests
{
    private static HookConfig DefaultConfig() => new(
        OnCritical: HookDecision.Block,
        OnHigh:     HookDecision.Block,
        OnMedium:   HookDecision.Block,
        OnLow:      HookDecision.Block,
        Verbose:    false);

    [Fact]
    public async Task TextResource_Scanned_AndForwarded()
    {
        await using var h = await StartHarnessAsync();
        h.Fake.EnqueueResourceResult(new ReadResourceResult
        {
            Contents =
            [
                new TextResourceContents
                {
                    Uri = "file:///hello.txt",
                    MimeType = "text/plain",
                    Text = "hello world",
                },
            ],
        });

        var (result, stderr) = await CaptureStderrAsync(() =>
            h.DriverClient.ReadResourceAsync("file:///hello.txt", cancellationToken: h.Cts.Token));

        Assert.Single(h.Fake.ReceivedResourceReads);
        Assert.Single(result.Contents);
        // Allowed text content produces an "allow" log line, not "skipped".
        Assert.Contains("event=resources_read", stderr, StringComparison.Ordinal);
        Assert.Contains("action=allow", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task JsonResource_Scanned()
    {
        await using var h = await StartHarnessAsync();
        h.Fake.EnqueueResourceResult(new ReadResourceResult
        {
            Contents =
            [
                new TextResourceContents
                {
                    Uri = "file:///data.json",
                    MimeType = "application/json",
                    Text = "{\"x\":1}",
                },
            ],
        });

        var (result, stderr) = await CaptureStderrAsync(() =>
            h.DriverClient.ReadResourceAsync("file:///data.json", cancellationToken: h.Cts.Token));

        Assert.Single(result.Contents);
        Assert.Contains("action=allow", stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("reason=mime", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BlobResource_Skipped_WithStderrLog()
    {
        await using var h = await StartHarnessAsync();
        h.Fake.EnqueueResourceResult(new ReadResourceResult
        {
            Contents =
            [
                new BlobResourceContents
                {
                    Uri = "file:///pic.png",
                    MimeType = "image/png",
                    // Ascii-only bytes that happen to be valid base64 chars — works around an
                    // SDK quirk where ResourceContents.Converter writes the byte memory as a
                    // raw string but expects to read it as base64.
                    Blob = new ReadOnlyMemory<byte>(System.Text.Encoding.ASCII.GetBytes("PNGdata1")),
                },
            ],
        });

        var (result, stderr) = await CaptureStderrAsync(() =>
            h.DriverClient.ReadResourceAsync("file:///pic.png", cancellationToken: h.Cts.Token));

        Assert.Single(result.Contents);
        Assert.Contains("event=resources_read", stderr, StringComparison.Ordinal);
        Assert.Contains("action=skipped", stderr, StringComparison.Ordinal);
        Assert.Contains("reason=mime", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NonTextMime_Skipped_WithStderrLog()
    {
        await using var h = await StartHarnessAsync();
        h.Fake.EnqueueResourceResult(new ReadResourceResult
        {
            Contents =
            [
                new TextResourceContents
                {
                    Uri = "file:///bin.dat",
                    MimeType = "application/octet-stream",
                    Text = "Z3JlZXRpbmdz",
                },
            ],
        });

        var (_, stderr) = await CaptureStderrAsync(() =>
            h.DriverClient.ReadResourceAsync("file:///bin.dat", cancellationToken: h.Cts.Token));

        Assert.Contains("action=skipped", stderr, StringComparison.Ordinal);
        Assert.Contains("reason=mime", stderr, StringComparison.Ordinal);
        Assert.Contains("mime=application/octet-stream", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OversizeText_Skipped_WithStderrLog()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_MAX_SCAN_BYTES", "100");
        try
        {
            await using var h = await StartHarnessAsync();
            // 80 unicorns (4 UTF-8 bytes each) = 320 bytes > 100.
            var oversized = string.Concat(Enumerable.Repeat("🦄", 80));
            h.Fake.EnqueueResourceResult(new ReadResourceResult
            {
                Contents =
                [
                    new TextResourceContents
                    {
                        Uri = "file:///big.txt",
                        MimeType = "text/plain",
                        Text = oversized,
                    },
                ],
            });

            var (_, stderr) = await CaptureStderrAsync(() =>
                h.DriverClient.ReadResourceAsync("file:///big.txt", cancellationToken: h.Cts.Token));

            Assert.Contains("action=skipped", stderr, StringComparison.Ordinal);
            Assert.Contains("reason=oversize", stderr, StringComparison.Ordinal);
            Assert.Contains("bytes=320", stderr, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_MAX_SCAN_BYTES", null);
        }
    }

    [Fact]
    public async Task CustomScanMimes_HonorsAllowlist()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_SCAN_MIMES", "application/x-custom");
        try
        {
            await using var h = await StartHarnessAsync();
            h.Fake.EnqueueResourceResult(new ReadResourceResult
            {
                Contents =
                [
                    new TextResourceContents
                    {
                        Uri = "file:///a.custom",
                        MimeType = "application/x-custom",
                        Text = "hello",
                    },
                    new TextResourceContents
                    {
                        Uri = "file:///b.txt",
                        MimeType = "text/plain",
                        Text = "world",
                    },
                ],
            });

            var (_, stderr) = await CaptureStderrAsync(() =>
                h.DriverClient.ReadResourceAsync("file:///mixed", cancellationToken: h.Cts.Token));

            // text/plain should now be skipped (not in custom allowlist), x-custom should not.
            Assert.Contains("mime=text/plain", stderr, StringComparison.Ordinal);
            Assert.Contains("reason=mime", stderr, StringComparison.Ordinal);
            Assert.Contains("action=allow", stderr, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_SCAN_MIMES", null);
        }
    }

    [Fact]
    public async Task ThreatDetected_ThrowsMcpException()
    {
        const string phrase = "execute arbitrary code on the remote server via tool manipulation";

        await using var h = await StartHarnessAsync();
        h.Fake.EnqueueResourceResult(new ReadResourceResult
        {
            Contents =
            [
                new TextResourceContents
                {
                    Uri = "file:///evil.txt",
                    MimeType = "text/plain",
                    Text = phrase,
                },
            ],
        });

        var ex = await Assert.ThrowsAnyAsync<McpException>(async () =>
            await h.DriverClient.ReadResourceAsync("file:///evil.txt", cancellationToken: h.Cts.Token));

        Assert.Contains("Blocked by AI.Sentinel", ex.Message, StringComparison.Ordinal);
    }

    private static async Task<(T Result, string Stderr)> CaptureStderrAsync<T>(Func<ValueTask<T>> action)
    {
        var prev = Console.Error;
        var sw = new StringWriter();
        Console.SetError(sw);
        try
        {
            var r = await action().ConfigureAwait(false);
            return (r, sw.ToString());
        }
        finally
        {
            Console.SetError(prev);
        }
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

    private static async Task<ProxyHarness> StartHarnessAsync()
    {
        var fake = new FakeMcpServer
        {
            AdvertisedCapabilities = new ServerCapabilities
            {
                Tools = new ToolsCapability(),
                Prompts = new PromptsCapability(),
                Resources = new ResourcesCapability(),
            },
        };
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
