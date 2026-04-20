using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelPipelineTests
{
    private static SentinelPipeline Build(IDetector[]? detectors = null, IChatClient? inner = null)
    {
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline(detectors ?? [], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        return new SentinelPipeline(inner ?? new TestChatClient("hello"), pipeline, audit, engine, opts);
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
}
