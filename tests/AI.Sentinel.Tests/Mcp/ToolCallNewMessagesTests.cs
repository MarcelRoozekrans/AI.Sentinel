using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Mcp;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

// #424. The tools/call request scan marks nothing as new; the response scan marks the result, index 1, as new.
public class ToolCallNewMessagesTests
{
    private sealed class CapturingDetector : IDetector
    {
        public List<SentinelContext> Seen { get; } = [];
        public DetectorId Id { get; } = new("TEST-CAPTURE");
        public DetectorCategory Category => DetectorCategory.Operational;

        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            Seen.Add(ctx);
            return ValueTask.FromResult(DetectionResult.Clean(Id));
        }
    }

    private sealed class NullClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private static SentinelPipeline Build(CapturingDetector capture)
    {
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline([capture], configurations: null, reviewer: null, redactByDefault: true);
        return new SentinelPipeline(new NullClient(), pipeline, new RingBufferAuditStore(100), new InterventionEngine(opts, null), opts);
    }

    private static RequestContext<CallToolRequestParams> BuildRequestContext(CallToolRequestParams parameters)
    {
        var ctx = (RequestContext<CallToolRequestParams>)RuntimeHelpers.GetUninitializedObject(
            typeof(RequestContext<CallToolRequestParams>));
        ctx.Params = parameters;
        return ctx;
    }

    private static async Task<CapturingDetector> CallAsync(CallToolResult result, PlaceholderStore? placeholders = null)
    {
        var capture = new CapturingDetector();
        var filter = ToolCallInterceptor.Create(Build(capture), TextWriter.Null, placeholders: placeholders);
        var handler = filter((_, _) => new ValueTask<CallToolResult>(result));

        _ = await handler(BuildRequestContext(new CallToolRequestParams { Name = "read" }), TestContext.Current.CancellationToken);
        return capture;
    }

    private static CallToolResult TextResult() =>
        new() { Content = [new TextContentBlock { Text = "result text" }] };

    [Fact]
    public async Task ToolCall_RequestScan_NewFromIsZero()
    {
        var capture = await CallAsync(TextResult());

        Assert.Equal(0, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task ToolCall_ResponseScan_ResultIsTheOnlyNewMessage()
    {
        var capture = await CallAsync(TextResult());

        Assert.Equal(2, capture.Seen[1].Messages.Count);
        Assert.Equal(1, capture.Seen[1].NewMessagesFrom);
    }

    [Fact]
    public async Task ToolCall_RedactedResponseScan_ResultIsTheOnlyNewMessage()
    {
        var capture = await CallAsync(TextResult(), new PlaceholderStore(PlaceholderStore.DefaultIdleExpiry));

        Assert.Equal(2, capture.Seen[1].Messages.Count);
        Assert.Equal(1, capture.Seen[1].NewMessagesFrom);
    }

    [Fact]
    public async Task ToolCall_EmptyResult_NewRangeIsEmpty()
    {
        var capture = await CallAsync(new CallToolResult());

        Assert.Single(capture.Seen[1].Messages);
        Assert.Equal(1, capture.Seen[1].NewMessagesFrom);
    }
}
