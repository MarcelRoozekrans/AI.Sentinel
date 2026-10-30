using System.IO.Pipelines;
using System.Text.RegularExpressions;
using AI.Sentinel.Audit;
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

/// <summary>End to end through the proxy: placeholders minted in one tool result come back as values in the
/// arguments of a later tool call, PII only, until they expire.</summary>
[Collection("NonParallel")]
public partial class McpRedactionProxyTests
{
    private const string Email = "jan@example.com";
    private const string ApiKey = "api_key=sk-test-0123456789abcdefghij";

    [GeneratedRegex(@"\[EMAIL_1_[a-z][a-z0-9]{5}\]", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex EmailToken();

    [GeneratedRegex(@"\[API_KEY_1_[a-z][a-z0-9]{5}\]", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ApiKeyToken();

    private static HookConfig AllSeverities(HookDecision decision, bool redact = true) => new()
    {
        OnCritical = decision,
        OnHigh = decision,
        OnMedium = decision,
        OnLow = decision,
        RedactToolResults = redact,
    };

    private static string TextOf(CallToolResult result) =>
        Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text;

    private static string StringArg(CallToolRequestParams call, string key) =>
        call.Arguments![key].GetString()!;

    private static async Task<string> ReadFileAsync(ProxyHarness h, string returns)
    {
        h.Fake.EnqueueToolResult(new CallToolResult { Content = [new TextContentBlock { Text = returns }] });
        var result = await h.DriverClient.CallToolAsync(
            toolName: "read_file",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["path"] = "/tmp/contacts.txt" },
            cancellationToken: h.Cts.Token);
        return TextOf(result);
    }

    [Fact]
    public async Task LookupThenAct_PiiRestored_SecretNot()
    {
        await using var h = await StartHarnessAsync(AllSeverities(HookDecision.Warn));

        var seen = await ReadFileAsync(h, $"contact {Email} {ApiKey}");
        var emailToken = EmailToken().Match(seen).Value;
        var keyToken = ApiKeyToken().Match(seen).Value;
        Assert.NotEmpty(emailToken);
        Assert.NotEmpty(keyToken);
        Assert.DoesNotContain(Email, seen, StringComparison.Ordinal);

        _ = await h.DriverClient.CallToolAsync(
            toolName: "send",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = emailToken, ["key"] = keyToken },
            cancellationToken: h.Cts.Token);

        var sent = h.Fake.ReceivedToolCalls[1];
        Assert.Equal(Email, StringArg(sent, "to"));
        Assert.Equal(keyToken, StringArg(sent, "key"));
    }

    [Fact]
    public async Task ToolResult_EchoingEarlierPlaceholder_IsNotBlocked()
    {
        await using var h = await StartHarnessAsync(AllSeverities(HookDecision.Block));

        var emailToken = EmailToken().Match(await ReadFileAsync(h, $"contact {Email}")).Value;
        Assert.NotEmpty(emailToken);

        h.Fake.EnqueueToolResult(new CallToolResult { Content = [new TextContentBlock { Text = $"results for {emailToken}" }] });
        var echoed = await h.DriverClient.CallToolAsync(
            toolName: "search",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["q"] = emailToken },
            cancellationToken: h.Cts.Token);

        Assert.Equal($"results for {emailToken}", TextOf(echoed));
        Assert.Equal(Email, StringArg(h.Fake.ReceivedToolCalls[1], "q"));
    }

    [Fact]
    public async Task ExpiredPlaceholder_ReachesToolLiteral()
    {
        await using var h = await StartHarnessAsync(
            AllSeverities(HookDecision.Warn), placeholderIdleExpiry: TimeSpan.FromMilliseconds(1));

        var emailToken = EmailToken().Match(await ReadFileAsync(h, $"contact {Email}")).Value;
        Assert.NotEmpty(emailToken);
        await Task.Delay(50, TestContext.Current.CancellationToken);

        _ = await h.DriverClient.CallToolAsync(
            toolName: "send",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = emailToken },
            cancellationToken: h.Cts.Token);

        Assert.Equal(emailToken, StringArg(h.Fake.ReceivedToolCalls[1], "to"));
    }

    [Fact]
    public async Task RedactOff_ArgumentsAndResultsUntouched()
    {
        await using var h = await StartHarnessAsync(AllSeverities(HookDecision.Warn, redact: false));

        var seen = await ReadFileAsync(h, $"contact {Email}");

        Assert.Equal($"contact {Email}", seen);
        _ = await h.DriverClient.CallToolAsync(
            toolName: "send",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = "[EMAIL_1_k3f9x2]" },
            cancellationToken: h.Cts.Token);
        Assert.Equal("[EMAIL_1_k3f9x2]", StringArg(h.Fake.ReceivedToolCalls[1], "to"));
    }

    private const int SmallBudget = 1024;

    /// <summary>Prose, so no detector but the scan budget has anything to say about it.</summary>
    private static string Filler(int bytes)
    {
        var text = string.Concat(Enumerable.Repeat("the quick brown fox jumps over the lazy dog ", bytes / 44 + 1));
        return text[..bytes];
    }

    private static bool IsScanLimit(AuditEntry e) => string.Equals(e.DetectorId, "SEC-00", StringComparison.Ordinal);

    // #439: a tool result over SENTINEL_MCP_MAX_SCAN_BYTES is blocked as SEC-00, redacting or not. 4.1 truncated the
    // scan text, or forwarded the item unredacted as oversize, and let the rest through unscanned.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ToolResultOverBudget_BlockedWithSec00(bool redact)
    {
        var audit = new RingBufferAuditStore(capacity: 64);
        await using var h = await StartHarnessAsync(new HookConfig { RedactToolResults = redact }, maxScanBytes: SmallBudget, auditStore: audit);
        h.Fake.EnqueueToolResult(new CallToolResult { Content = [new TextContentBlock { Text = Filler(SmallBudget + 1) }] });

        var ex = await Assert.ThrowsAnyAsync<McpException>(async () => await h.DriverClient.CallToolAsync(
            toolName: "read_file",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["path"] = "/tmp/big.txt" },
            cancellationToken: h.Cts.Token));

        Assert.Contains("SEC-00", ex.Message, StringComparison.Ordinal);
        Assert.Contains(await RecordingAuditForwarder.ReadAllAsync(audit), IsScanLimit);
    }

    // The original bypass: an injection placed after the budget's worth of filler was never scanned.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ToolResultInjectionPastCap_Blocked(bool redact)
    {
        await using var h = await StartHarnessAsync(new HookConfig { RedactToolResults = redact }, maxScanBytes: SmallBudget);
        h.Fake.EnqueueToolResult(new CallToolResult
        {
            Content = [new TextContentBlock { Text = Filler(SmallBudget) + " " + DetectorExamples.PromptInjectionHigh }],
        });

        var ex = await Assert.ThrowsAnyAsync<McpException>(async () => await h.DriverClient.CallToolAsync(
            toolName: "read_file",
            arguments: new Dictionary<string, object?>(StringComparer.Ordinal) { ["path"] = "/tmp/big.txt" },
            cancellationToken: h.Cts.Token));

        Assert.Contains("Blocked by AI.Sentinel", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PromptGetOverBudget_Blocked(bool redact)
    {
        var audit = new RingBufferAuditStore(capacity: 64);
        await using var h = await StartHarnessAsync(new HookConfig { RedactToolResults = redact }, maxScanBytes: SmallBudget, auditStore: audit);
        h.Fake.EnqueuePromptResult(new GetPromptResult
        {
            Messages = [new PromptMessage { Role = Role.User, Content = new TextContentBlock { Text = Filler(SmallBudget + 1) } }],
        });

        var ex = await Assert.ThrowsAnyAsync<McpException>(async () =>
            await h.DriverClient.GetPromptAsync("big", cancellationToken: h.Cts.Token));

        Assert.Contains("SEC-00", ex.Message, StringComparison.Ordinal);
        Assert.Contains(await RecordingAuditForwarder.ReadAllAsync(audit), IsScanLimit);
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

    private static async Task<ProxyHarness> StartHarnessAsync(
        HookConfig config, TimeSpan? placeholderIdleExpiry = null, int maxScanBytes = 262144, IAuditStore? auditStore = null)
    {
        var fake = new FakeMcpServer();
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
            config: config,
            preset: DetectorPreset.Security, // the default, so PII redaction is tested as users get it
            maxScanBytes: maxScanBytes,
            stderr: TextWriter.Null,
            ct: cts.Token,
            embeddingGenerator: new ExactMatchEmbeddingGenerator(),
            auditStore: auditStore,
            placeholderIdleExpiry: placeholderIdleExpiry);

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
