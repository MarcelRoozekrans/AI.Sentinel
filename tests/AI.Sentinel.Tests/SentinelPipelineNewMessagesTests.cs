using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Redaction;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests;

// #424. Each scan path tells the detectors which of its messages are new: on the prompt scan those after the
// last assistant message, a trailing assistant prefill aside, on the response scan all of them, on the host path
// all after the request context.
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
        var pipeline = new DetectionPipeline(detectors, configurations: null, reviewer: null, redactByDefault: redactByDefault);
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

    // An assistant prefill, such as an opening "{", ends the request. The user turn before it is still new.
    [Fact]
    public async Task PromptScan_EndsWithAssistantPrefill_UserTurnIsNew()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "a"), new ChatMessage(ChatRole.Assistant, "{")],
            null, TestContext.Current.CancellationToken);

        Assert.Equal(0, capture.Seen[0].NewMessagesFrom);
    }

    [Fact]
    public async Task PromptScan_PrefillAfterHistory_NewFromIsAfterThePreviousAssistant()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(
            [
                new ChatMessage(ChatRole.User, "a"),
                new ChatMessage(ChatRole.Assistant, "b"),
                new ChatMessage(ChatRole.User, "c"),
                new ChatMessage(ChatRole.Assistant, "{"),
            ],
            null, TestContext.Current.CancellationToken);

        Assert.Equal(2, capture.Seen[0].NewMessagesFrom);
    }

    [Theory]
    [InlineData("", 0)]
    [InlineData("u", 0)]
    [InlineData("a", 0)]
    [InlineData("ua", 0)]
    [InlineData("uaa", 0)]
    [InlineData("uau", 2)]
    [InlineData("uaua", 2)]
    [InlineData("uauaa", 2)]
    [InlineData("suaut", 3)]
    public void NewFromAfterLastAssistant_SkipsATrailingPrefill(string roles, int expected)
    {
        var messages = roles.Select(r => new ChatMessage(
            r switch { 'a' => ChatRole.Assistant, 's' => ChatRole.System, 't' => ChatRole.Tool, _ => ChatRole.User },
            "x")).ToList();

        Assert.Equal(expected, SentinelPipeline.NewFromAfterLastAssistant(messages));
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

    // The public API marks every message new, and the instructions message it prepends is new too.
    [Fact]
    public async Task ScanMessagesAsync_WithInstructions_ScoresTheInstructions()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).ScanMessagesAsync(
            UserAssistantUser(), new ChatOptions { Instructions = "x" }, ct: TestContext.Current.CancellationToken);

        var ctx = Assert.Single(capture.Seen);
        Assert.Equal(4, ctx.Messages.Count);
        Assert.Equal(0, ctx.NewMessagesFrom);
    }

    // A caller's non-zero index moves past a prepended instructions message; zero stays zero.
    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(0, 1, 0)]
    [InlineData(2, 0, 2)]
    [InlineData(2, 1, 3)]
    public void ShiftForInstructions_ShiftsOnlyANonZeroIndex(int newMessagesFrom, int shift, int expected) =>
        Assert.Equal(expected, SentinelPipeline.ShiftForInstructions(newMessagesFrom, shift));

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

    // #439, through the real tool loop. The model calls the tool twice; the first result carries a secret. Redaction is
    // off and criticals only log, so the loop runs to its end. Round 2 judges the secret; round 3 sends the same
    // history again and must not report it a second time.
    [Fact]
    public async Task ToolLoop_SecretInRound1Result_FlaggedOnceNotInRound2()
    {
        var model = new Redaction.RedactionPipelineTests.RecordingModel(messages =>
        {
            var results = messages.SelectMany(m => m.Contents).OfType<FunctionResultContent>().Count();
            return results >= 2
                ? new ChatMessage(ChatRole.Assistant, "done")
                : new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c" + results, "Lookup", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })]);
        });
        var h = Redaction.RedactionPipelineTests.Build("F>S", model, o => { o.RedactByDefault = false; o.OnCritical = SentinelAction.Log; });
        var calls = 0;
        var options = new ChatOptions { Tools = [AIFunctionFactory.Create((string id) => ++calls == 1 ? "password=hunter2secretvalue" : "all clean here", "Lookup")] };

        var response = await h.Client.GetResponseAsync([new ChatMessage(ChatRole.User, "look it up")], options, TestContext.Current.CancellationToken);

        Assert.Equal("done", response.Text);
        Assert.Equal(3, model.Calls);
        var entries = await RecordingAuditForwarder.ReadAllAsync(h.Audit);
        Assert.Single(entries, e => string.Equals(e.DetectorId, "SEC-02", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Oversize_CredentialPastCap_NotReportedButScanCritical()
    {
        var opts = new SentinelOptions { RedactByDefault = false, MaxScanBytes = 100 };
        var detection = new DetectionPipeline([new CredentialExposureDetector()], configurations: null, reviewer: null, redactByDefault: false);
        var pipeline = new SentinelPipeline(new RecordingClient(), detection, new RingBufferAuditStore(100), new InterventionEngine(opts, null), opts);
        var text = new string('a', 200) + " password=hunter2secretvalue";

        var result = await pipeline.GetResponseResultAsync([new ChatMessage(ChatRole.User, text)], null, TestContext.Current.CancellationToken);

        var error = Assert.IsType<SentinelError.ThreatDetected>(result.Error);
        Assert.Contains(error.Detections, d => string.Equals(d.DetectorId.Value, "SEC-00", StringComparison.Ordinal) && d.Severity == Severity.Critical);
        Assert.DoesNotContain(error.Detections, d => string.Equals(d.DetectorId.Value, "SEC-02", StringComparison.Ordinal));
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
