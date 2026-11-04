using System.IO.Pipelines;
using AI.Sentinel.Mcp.Cli;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

/// <summary>Semantic approvals end to end in the MCP proxy: a config with only a <c>semantic</c> block, scoring an
/// HTTP-shaped tool on its method and URL, holds a destructive call for approval (#477).</summary>
[Collection("NonParallel")]
public class McpCliSemanticApprovalTests : McpAuditOffFixtureBase
{
    private const string Tool = "http_request";
    private const string DestructiveUrl = "https://api.example.com/v1/users?all=true";

    private const string InertEvent = "event=semantic_approval_inert";

    private static async Task<(Exception? Error, int Forwarded, string Stderr)> CallThroughProxyAsync(
        string method, string url, bool withGenerator = true)
    {
        var dir = HookAuditTestSupport.NewTempDir();
        var previous = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");
        try
        {
            var configPath = Path.Combine(dir, "approvals.json");
            await File.WriteAllTextAsync(configPath, $$"""
                { "backend": "in-memory",
                  "semantic": { "examples": ["{{DestructiveUrl}}"],
                                "tools": { "{{Tool}}": { "role": "Ops", "paths": ["$.method", "$.url"] } } } }
                """, TestContext.Current.CancellationToken);
            Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", configPath);

            await using var fake = new FakeMcpServer();
            var targetTransport = fake.Start();
            var hostToProxy = new Pipe();
            var proxyToHost = new Pipe();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var stderr = new StringWriter();

            var run = ProxyCommand.RunAsync(
                ["proxy", "--target", "fake"], TextReader.Null, TextWriter.Null, TextWriter.Synchronized(stderr), cts.Token,
                () => (new StreamServerTransport(hostToProxy.Reader.AsStream(), proxyToHost.Writer.AsStream(),
                           "proxy-server", NullLoggerFactory.Instance),
                       targetTransport),
                embeddingGenerator: withGenerator ? new ExactMatchEmbeddingGenerator() : null);

            Exception? error = null;
            await using (var driver = await McpClient.CreateAsync(
                new StreamClientTransport(hostToProxy.Writer.AsStream(), proxyToHost.Reader.AsStream(), NullLoggerFactory.Instance),
                clientOptions: null, loggerFactory: NullLoggerFactory.Instance, cancellationToken: cts.Token))
            {
                try
                {
                    _ = await driver.CallToolAsync(Tool,
                        new Dictionary<string, object?>(StringComparer.Ordinal) { ["method"] = method, ["url"] = url },
                        cancellationToken: cts.Token);
                }
                catch (McpException ex)
                {
                    error = ex;
                }

                await cts.CancelAsync();
                Assert.Equal(0, await run);
            }

            return (error, fake.ReceivedToolCalls.Count, stderr.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", previous);
            HookAuditTestSupport.DeleteDir(dir);
        }
    }

    [Fact]
    public async Task Semantic_DestructiveHttpCall_RequiresApproval()
    {
        var (error, forwarded, _) = await CallThroughProxyAsync("DELETE", DestructiveUrl);

        Assert.NotNull(error);
        Assert.Contains($"semantic:{Tool}#", error.Message, StringComparison.Ordinal);
        Assert.Contains("Semantic match", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, forwarded);
    }

    [Fact]
    public async Task Semantic_BenignHttpCall_IsForwarded()
    {
        var (error, forwarded, stderr) = await CallThroughProxyAsync("GET", "https://api.example.com/v1/users/42");

        Assert.Null(error);
        Assert.Equal(1, forwarded);
        Assert.DoesNotContain(InertEvent, stderr, StringComparison.Ordinal);
    }

    // No logging provider in the proxy, so the guard's warning that the layer is inert goes to stderr, once.
    [Fact]
    public async Task Semantic_NoEmbeddingGenerator_WarnsOnceThatTheLayerIsInert()
    {
        var (error, forwarded, stderr) = await CallThroughProxyAsync(
            "GET", "https://api.example.com/v1/users/42", withGenerator: false);

        Assert.Null(error);
        Assert.Equal(1, forwarded);
        Assert.Single(stderr.Split('\n'), l => l.Contains(InertEvent, StringComparison.Ordinal));
    }
}
