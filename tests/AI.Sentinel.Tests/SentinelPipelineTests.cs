using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelPipelineTests
{
    private static SentinelPipeline Build(
        IDetector[]? detectors = null,
        IChatClient? inner = null,
        IAlertSink? alertSink = null)
    {
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline(detectors ?? [], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        return new SentinelPipeline(inner ?? new TestChatClient("hello"), pipeline, audit, engine, opts, alertSink);
    }

    [Fact]
    public async Task GetResponseResultAsync_CleanMessage_ReturnsSuccess()
    {
        var result = await Build().GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], null, default);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task GetResponseResultAsync_QuarantineThreat_ReturnsFailure()
    {
        var result = await Build([new AlwaysCriticalDetector()]).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], null, default);
        Assert.True(result.IsFailure);
        Assert.IsType<SentinelError.ThreatDetected>(result.Error);
    }

    [Fact]
    public async Task GetResponseResultAsync_InnerClientThrows_ReturnsPipelineFailure()
    {
        var result = await Build(inner: new ThrowingChatClient()).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], null, default);
        Assert.True(result.IsFailure);
        Assert.IsType<SentinelError.PipelineFailure>(result.Error);
    }

    [Fact]
    public async Task GetResponseResultAsync_QuarantineThreat_CallsAlertSinkOnce()
    {
        var sink = new RecordingAlertSink();
        _ = await Build([new AlwaysCriticalDetector()], alertSink: sink).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hostile")], null, default);
        // Fire-and-forget is async; give it a moment to complete.
        await Task.Delay(100);
        Assert.Equal(1, sink.CallCount);
        Assert.IsType<SentinelError.ThreatDetected>(sink.LastError);
    }

    [Fact]
    public async Task GetResponseResultAsync_CleanMessage_DoesNotCallAlertSink()
    {
        var sink = new RecordingAlertSink();
        _ = await Build(alertSink: sink).GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], null, default);
        Assert.Equal(0, sink.CallCount);
    }

    [Fact]
    public async Task GetResponseResultAsync_CleanPromptMaliciousResponse_ReturnsFailure()
    {
        // inner client returns a message that the detector flags
        var inner = new TestChatClient("malicious reply");
        var result = await Build([new ResponseOnlyDetector()], inner: inner)
            .GetResponseResultAsync([new ChatMessage(ChatRole.User, "clean prompt")], null, default);
        Assert.True(result.IsFailure);
        Assert.IsType<SentinelError.ThreatDetected>(result.Error);
    }

    private sealed class ResponseOnlyDetector : IDetector
    {
        public DetectorId Id => new("RESP-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            var hasAssistantMessage = ctx.Messages.Any(m => m.Role == ChatRole.Assistant);
            return hasAssistantMessage
                ? ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "response threat"))
                : ValueTask.FromResult(DetectionResult.Clean(Id));
        }
    }

    private sealed class AlwaysCriticalDetector : IDetector
    {
        public DetectorId Id => new("TEST-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "forced critical"));
    }

    private sealed class TestChatClient(string reply) : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, reply)]));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotSupportedException("Streaming not needed in this test double.");

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }

    private sealed class ThrowingChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => Task.FromException<ChatResponse>(new HttpRequestException("simulated network failure"));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotSupportedException();

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }

    private sealed class RecordingAlertSink : IAlertSink
    {
        private int _callCount;
        public int CallCount => _callCount;
        public SentinelError? LastError { get; private set; }

        public ValueTask SendAsync(SentinelError error, CancellationToken ct)
        {
            Interlocked.Increment(ref _callCount);
            LastError = error;
            return ValueTask.CompletedTask;
        }
    }
}
