using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests;

// ChatOptions.Instructions reaches the model as a system prompt, so the detectors must judge it too.
public class SentinelPipelineInstructionsTests
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

    private static ChatOptions WithInstructions(string text) => new() { Instructions = text };

    [Fact]
    public async Task GetResponse_InstructionsAreScannedAsASystemMessage()
    {
        var capture = new CapturingDetector();
        var result = await Build([capture]).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], WithInstructions("Be terse."), TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        var prompt = capture.Seen[0];
        Assert.Equal(ChatRole.System, prompt.Messages[0].Role);
        Assert.Equal("Be terse.", prompt.Messages[0].Text);
        Assert.Equal("Be terse.", prompt.SystemPrompt);
    }

    [Fact]
    public async Task GetResponse_InstructionsAndSystemMessage_BothFormTheSystemPrompt()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(
            [new ChatMessage(ChatRole.System, "You are a bot."), new ChatMessage(ChatRole.User, "Hello")],
            WithInstructions("Be terse."), TestContext.Current.CancellationToken);

        // Both the prompt scan and the response scan compare against everything the model was told.
        foreach (var ctx in capture.Seen)
        {
            Assert.Contains("Be terse.", ctx.SystemPrompt, StringComparison.Ordinal);
            Assert.Contains("You are a bot.", ctx.SystemPrompt, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task GetResponse_NoInstructions_ScansTheMessagesUnchanged()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], new ChatOptions(), TestContext.Current.CancellationToken);

        var prompt = Assert.Single(capture.Seen[0].Messages);
        Assert.Equal(ChatRole.User, prompt.Role);
        Assert.Null(capture.Seen[0].SystemPrompt);
    }

    [Fact]
    public async Task GetResponse_CredentialInInstructions_IsDetectedWhenNotRedacted()
    {
        var result = await Build([new CredentialExposureDetector()], redactByDefault: false).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")],
            WithInstructions("Use api_key=sk-abcdefghijklmnopqrstuvwxyz0123456789 for lookups."),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsFailure);
        Assert.IsType<SentinelError.ThreatDetected>(result.Error);
    }

    [Fact]
    public async Task GetResponseStreaming_InstructionsAreScanned()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).GetStreamingResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], WithInstructions("Be terse."), TestContext.Current.CancellationToken);

        Assert.Equal("Be terse.", capture.Seen[0].Messages[0].Text);
        Assert.Equal("Be terse.", capture.Seen[0].SystemPrompt);
    }

    [Fact]
    public async Task ScanMessages_InstructionsAreScanned()
    {
        var capture = new CapturingDetector();
        _ = await Build([capture]).ScanMessagesAsync(
            [new ChatMessage(ChatRole.User, "Hello")], WithInstructions("Be terse."), ct: TestContext.Current.CancellationToken);

        Assert.Equal("Be terse.", capture.Seen[0].Messages[0].Text);
        Assert.Equal("Be terse.", capture.Seen[0].SystemPrompt);
    }

    [Fact]
    public async Task GetResponse_CallerMessagesAreNotChanged()
    {
        var model = new RecordingClient();
        var opts = new SentinelOptions();
        var pipeline = new SentinelPipeline(model, new DetectionPipeline([], null, null), new RingBufferAuditStore(10), new InterventionEngine(opts, null), opts);

        _ = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], WithInstructions("Be terse."), TestContext.Current.CancellationToken);

        // The instructions reach the model through the options only, never as an extra message.
        var sent = Assert.Single(model.Messages);
        Assert.Equal(ChatRole.User, sent.Role);
        Assert.Equal("Be terse.", model.Options?.Instructions);
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
