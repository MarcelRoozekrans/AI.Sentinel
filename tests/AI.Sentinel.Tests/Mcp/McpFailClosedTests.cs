using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Mcp;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;
using static AI.Sentinel.Tests.Mcp.McpFailClosedFixture;

namespace AI.Sentinel.Tests.Mcp;

public class McpFailClosedTests
{
    [Fact]
    public void Block_NamesTheTypeOnly()
        => AssertFailClosed(McpFailClosed.Block(new InvalidOperationException(LeakMarker)));

    [Fact]
    public async Task ThrowingPipeline_DelegatesBeforeThrowFromCall()
    {
        var pipeline = ThrowingPipeline(throwFromCall: 2);
        var messages = new[] { new ChatMessage(ChatRole.User, "hello") };
        var ct = TestContext.Current.CancellationToken;

        var first = await pipeline.ScanMessagesAsync(messages, ct: ct);
        Assert.Null(first);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await pipeline.ScanMessagesAsync(messages, ct: ct));
    }

    private static CallToolRequestParams ReadFile() => new()
    {
        Name = "read_file",
        Arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["path"] = JsonSerializer.SerializeToElement("/tmp/a.txt"),
        },
    };

    private sealed class Counter
    {
        public int Calls;

        public McpRequestHandler<CallToolRequestParams, CallToolResult> Next => (_, _) =>
        {
            Calls++;
            return new ValueTask<CallToolResult>(new CallToolResult { Content = [new TextContentBlock { Text = "ok" }] });
        };
    }

    private sealed class ThrowingAuditStore : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
            => throw new IOException(LeakMarker);

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct)
            => throw new NotSupportedException();
    }

    [Fact]
    public async Task ToolCall_RequestScanThrows_TargetIsNotCalled()
    {
        var stderr = new StringWriter();
        var next = new Counter();
        var handler = ToolCallInterceptor.Create(ThrowingPipeline(), stderr)(next.Next);

        var ex = await Assert.ThrowsAsync<McpProtocolException>(
            async () => await handler(Context(ReadFile()), TestContext.Current.CancellationToken));

        AssertFailClosed(ex);
        Assert.Equal(0, next.Calls);
        var log = stderr.ToString();
        Assert.Contains("decision=FailClosed tool=read_file phase=request reason=InvalidOperationException", log);
        Assert.DoesNotContain("FailOpen", log);
        Assert.DoesNotContain(LeakMarker, log);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ToolCall_ResponseScanThrows_BlocksResult(bool redacting)
    {
        var stderr = new StringWriter();
        var next = new Counter();
        var handler = ToolCallInterceptor.Create(
            ThrowingPipeline(throwFromCall: 2), stderr, placeholders: redacting ? NewStore() : null)(next.Next);

        var ex = await Assert.ThrowsAsync<McpProtocolException>(
            async () => await handler(Context(ReadFile()), TestContext.Current.CancellationToken));

        AssertFailClosed(ex);
        Assert.Equal(1, next.Calls);
        var log = stderr.ToString();
        Assert.Contains("decision=FailClosed tool=read_file phase=response reason=InvalidOperationException", log);
        Assert.DoesNotContain("FailOpen", log);
        Assert.DoesNotContain(LeakMarker, log);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(2, true)]
    public async Task ToolCall_FailClosed_WritesInternalErrorAuditEntry(int throwFromCall, bool redacting)
    {
        var store = new RingBufferAuditStore(16);
        var forwarder = new RecordingAuditForwarder();
        var handler = ToolCallInterceptor.Create(
            ThrowingPipeline(throwFromCall: throwFromCall), TextWriter.Null, audit: store, forwarders: [forwarder],
            placeholders: redacting ? NewStore() : null)(new Counter().Next);

        await Assert.ThrowsAsync<McpProtocolException>(
            async () => await handler(Context(ReadFile()), TestContext.Current.CancellationToken));

        var stored = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(store));
        Assert.Equal("AUTHZ-DENY", stored.DetectorId);
        Assert.Equal(SentinelDenyCodes.InternalError, stored.PolicyCode);
        Assert.Contains("InvalidOperationException", stored.Summary);
        Assert.DoesNotContain(LeakMarker, stored.Summary);
        await forwarder.WaitForAsync(1);
        Assert.Equal(stored.Hash, Assert.Single(forwarder.Entries).Hash);
    }

    [Fact]
    public async Task ToolCall_AuditStoreThrows_StillBlocks()
    {
        var stderr = new StringWriter();
        var handler = ToolCallInterceptor.Create(
            ThrowingPipeline(), stderr, audit: new ThrowingAuditStore())(new Counter().Next);

        var ex = await Assert.ThrowsAsync<McpProtocolException>(
            async () => await handler(Context(ReadFile()), TestContext.Current.CancellationToken));

        AssertFailClosed(ex);
        var log = stderr.ToString();
        Assert.Contains("decision=AuditFailed phase=fail_closed", log);
        Assert.DoesNotContain(LeakMarker, log);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(2, true)]
    public async Task ToolCall_Cancelled_Propagates(int throwFromCall, bool redacting)
    {
        var stderr = new StringWriter();
        var handler = ToolCallInterceptor.Create(
            ThrowingPipeline(() => new OperationCanceledException(), throwFromCall), stderr,
            placeholders: redacting ? NewStore() : null)(new Counter().Next);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await handler(Context(ReadFile()), TestContext.Current.CancellationToken));

        Assert.DoesNotContain("FailClosed", stderr.ToString());
    }
}
