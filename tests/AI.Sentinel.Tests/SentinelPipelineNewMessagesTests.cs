using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests;

// #424. Each scan path tells the detectors which of its messages are new: on the prompt scan those after the
// last assistant message, on the response scan all of them, on the host path all after the request context.
public class SentinelPipelineNewMessagesTests
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

    private static SentinelPipeline Build(IDetector[] detectors, bool redactByDefault = true)
    {
        var opts = new SentinelOptions { RedactByDefault = redactByDefault };
        var pipeline = new DetectionPipeline(detectors, configurations: null, escalationClient: null, redactByDefault: redactByDefault);
        return new SentinelPipeline(new RecordingClient(), pipeline, new RingBufferAuditStore(100), new InterventionEngine(opts, null), opts);
    }

    private static ChatMessage[] AgentLoop() =>
    [
        new(ChatRole.System, "s"),
        new(ChatRole.User, "a"),
        new(ChatRole.Assistant, "b"),
        new(ChatRole.User, "c"),
        new(ChatRole.Tool, "d"),
    ];

    private static ChatMessage[] UserAssistantUser() =>
    [
        new(ChatRole.User, "a"),
        new(ChatRole.Assistant, "b"),
        new(ChatRole.User, "c"),
    ];

    private static ChatMessage[] TwoUserMessages() =>
    [
        new(ChatRole.User, "a"),
        new(ChatRole.User, "b"),
    ];

    private static HostRedactionRequest HostRequest() => new()
    {
        Context = [new ChatMessage(ChatRole.User, "context one"), new ChatMessage(ChatRole.User, "context two")],
        Content = [HostContent.FromText("the content")],
        Unredactable = [new ChatMessage(ChatRole.Assistant, "too large to redact")],
    };

    [Fact]
    public async Task PromptScan_NewFromIsAfterTheLastAssistantMessage()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(AgentLoop(), null, TestContext.Current.CancellationToken);

        Assert.Equal(3, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task PromptScan_NoAssistantMessage_NewFromIsZero()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(TwoUserMessages(), null, TestContext.Current.CancellationToken);

        Assert.Equal(0, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task PromptScan_EndsWithAssistant_NewFromIsCount()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "a"), new ChatMessage(ChatRole.Assistant, "b")],
            null, TestContext.Current.CancellationToken);

        Assert.Equal(2, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task PromptScan_WithInstructions_CountsTheInstructionsMessage()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(
            UserAssistantUser(), new ChatOptions { Instructions = "Be terse." }, TestContext.Current.CancellationToken);

        Assert.Equal(4, capture.Seen[0].Messages.Count);
        Assert.Equal(3, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task StreamingPromptScan_UsesTheSameIndex()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetStreamingResultAsync(AgentLoop(), null, TestContext.Current.CancellationToken);

        Assert.Equal(3, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task ResponseScan_NewFromIsZero()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(AgentLoop(), null, TestContext.Current.CancellationToken);

        Assert.Equal(2, capture.Seen.Count);
        Assert.Equal(0, capture.Seen[1].NewMessagesFrom);
    }

    [Fact]
    public async Task ScanMessagesAsync_Public_NewFromIsZero()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).ScanMessagesAsync(UserAssistantUser(), ct: TestContext.Current.CancellationToken);

        Assert.Equal(0, Assert.Single(capture.Seen).NewMessagesFrom);
    }

    [Fact]
    public async Task ScanMessagesAsync_WithInstructions_ShiftsTheIndex()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).ScanMessagesAsync(
            UserAssistantUser(), new ChatOptions { Instructions = "x" }, ct: TestContext.Current.CancellationToken);

        var ctx = Assert.Single(capture.Seen);
        Assert.Equal(4, ctx.Messages.Count);
        Assert.Equal(1, ctx.NewMessagesFrom);
    }

    [Fact]
    public async Task ScanMessagesForFindings_PassesTheIndex()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).ScanMessagesForFindingsAsync(
            TwoUserMessages(), sessionId: null, newMessagesFrom: 1, TestContext.Current.CancellationToken);

        Assert.Equal(1, Assert.Single(capture.Seen).NewMessagesFrom);
    }

    [Fact]
    public async Task ScanMessagesExempting_IndexAboveCount_IsClamped()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).ScanMessagesExemptingAsync(
            TwoUserMessages(), sessionId: null, exemptPlaceholders: null, newMessagesFrom: 5, TestContext.Current.CancellationToken);

        Assert.Equal(2, Assert.Single(capture.Seen).NewMessagesFrom);
    }

    [Fact]
    public async Task RedactAndScan_NewFromIsTheContextCount()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).RedactAndScanAsync(HostRequest(), sessionId: null, TestContext.Current.CancellationToken);

        var ctx = Assert.Single(capture.Seen);
        Assert.Equal(4, ctx.Messages.Count);
        Assert.Equal(2, ctx.NewMessagesFrom);
    }

    [Fact]
    public async Task RedactAndScan_Redacting_NewFromIsTheContextCount()
    {
        var capture = new CapturingDetector();
        var result = await Build([capture, new CredentialExposureDetector()]).RedactAndScanAsync(
            HostRequest(), sessionId: null, TestContext.Current.CancellationToken);

        Assert.False(result.FellBack);
        var ctx = Assert.Single(capture.Seen);
        Assert.Equal(4, ctx.Messages.Count);
        Assert.Equal(2, ctx.NewMessagesFrom);
    }

    private sealed class RecordingClient : IChatClient
    {
        public List<ChatMessage> Messages { get; } = [];
        public ChatOptions? Options { get; private set; }

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            Messages.AddRange(messages);
            Options = options;
            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "fine, thanks")));
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => StreamAsync(messages, options);

        private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(IEnumerable<ChatMessage> messages, ChatOptions? options)
        {
            Messages.AddRange(messages);
            Options = options;
            await Task.Yield();
            yield return new ChatResponseUpdate(ChatRole.Assistant, "fine, thanks");
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
