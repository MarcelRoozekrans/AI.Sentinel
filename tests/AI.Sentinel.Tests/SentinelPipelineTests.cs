using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using Xunit;
using ZeroAlloc.Results;

namespace AI.Sentinel.Tests;

public class SentinelPipelineTests
{
    private static SentinelPipeline BuildCleanPipeline()
    {
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline([], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        var inner = new TestChatClient("hello");
        return new SentinelPipeline(inner, pipeline, audit, engine, opts);
    }

    [Fact]
    public async Task GetResponseResultAsync_CleanMessage_ReturnsSuccess()
    {
        var pipeline = BuildCleanPipeline();
        var result = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "Hello")], null, default);
        Assert.True(result.IsSuccess);
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
}
