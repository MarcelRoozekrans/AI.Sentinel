using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Mcp;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;
using static AI.Sentinel.Tests.Mcp.McpFailClosedFixture;

namespace AI.Sentinel.Tests.Mcp;

// #544. resources/read logs through StderrLogger to Console.Error, so these tests swap the console and must not
// run in parallel with other tests that do.
[Collection("NonParallel")]
public class McpFailClosedResourceTests
{
    private static TextResourceContents Text(string text) => new()
    {
        Uri = "file:///x.txt",
        MimeType = "text/plain",
        Text = text,
    };

    private static McpRequestHandler<ReadResourceRequestParams, ReadResourceResult> Returning(ReadResourceResult result)
        => (_, _) => new ValueTask<ReadResourceResult>(result);

    private static async Task<(McpProtocolException Ex, string Stderr)> BlockedAsync(
        McpRequestHandler<ReadResourceRequestParams, ReadResourceResult> handler)
    {
        var prev = Console.Error;
        var sw = new StringWriter();
        Console.SetError(sw);
        try
        {
            var ex = await Assert.ThrowsAsync<McpProtocolException>(async () => await handler(
                Context(new ReadResourceRequestParams { Uri = "file:///x.txt" }), TestContext.Current.CancellationToken));
            return (ex, sw.ToString());
        }
        finally
        {
            Console.SetError(prev);
        }
    }

    private static IDetectionPipeline RedactingPii()
        => new DetectionPipeline([new PiiLeakageDetector()], configurations: null, reviewer: null, redactByDefault: true);

    private static async Task<List<AuditEntry>> EntriesAsync(IAuditStore store)
    {
        var list = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, TestContext.Current.CancellationToken))
        {
            list.Add(e);
        }
        return list;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ResourceRead_ScanThrows_Blocks(bool redacting)
    {
        var result = new ReadResourceResult { Contents = [Text("hello")] };
        var handler = ResourceReadInterceptor.Create(
            ThrowingPipeline(), placeholders: redacting ? NewStore() : null)(Returning(result));

        var (ex, stderr) = await BlockedAsync(handler);

        AssertFailClosed(ex);
        Assert.Contains("fail_closed", stderr);
        Assert.Contains("InvalidOperationException", stderr);
        Assert.DoesNotContain("fail_open", stderr);
        Assert.DoesNotContain(LeakMarker, stderr);
    }

    [Fact]
    public async Task Redacting_NoItemThrows_RewritesItemOne()
    {
        // Positive control: with nothing throwing, item 1 is rewritten, so the "unchanged" test below means something.
        var store = new RingBufferAuditStore(100);
        var first = Text("mail a@example.com");
        var result = new ReadResourceResult { Contents = [first, Text("second")] };
        var handler = ResourceReadInterceptor.Create(
            ThrowingPipeline(throwFromCall: 3, inner: RedactingPii(), auditStore: store),
            placeholders: NewStore())(Returning(result));

        _ = await handler(Context(new ReadResourceRequestParams { Uri = "file:///x.txt" }), TestContext.Current.CancellationToken);

        Assert.DoesNotContain("a@example.com", first.Text);
        Assert.Contains(await EntriesAsync(store), e => string.Equals(e.PolicyCode, "REDACTED", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Redacting_OneItemThrows_BlocksWholeRead_NothingWrittenBack()
    {
        var store = new RingBufferAuditStore(100);
        var first = Text("mail a@example.com");
        var second = Text("second");
        var result = new ReadResourceResult { Contents = [first, second] };
        var handler = ResourceReadInterceptor.Create(
            ThrowingPipeline(throwFromCall: 2, inner: RedactingPii(), auditStore: store),
            placeholders: NewStore())(Returning(result));

        var (ex, stderr) = await BlockedAsync(handler);

        AssertFailClosed(ex);
        Assert.Contains("fail_closed", stderr);
        Assert.Equal("mail a@example.com", first.Text);
        Assert.Equal("second", second.Text);
        Assert.DoesNotContain(await EntriesAsync(store), e => string.Equals(e.PolicyCode, "REDACTED", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ResourceRead_Cancelled_Propagates(bool redacting)
    {
        var result = new ReadResourceResult { Contents = [Text("hello")] };
        var handler = ResourceReadInterceptor.Create(
            ThrowingPipeline(() => new OperationCanceledException()),
            placeholders: redacting ? NewStore() : null)(Returning(result));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await handler(
            Context(new ReadResourceRequestParams { Uri = "file:///x.txt" }), TestContext.Current.CancellationToken));
    }
}
