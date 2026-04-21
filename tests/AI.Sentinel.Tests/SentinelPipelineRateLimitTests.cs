using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelPipelineRateLimitTests
{
    private static SentinelPipeline Build(int? maxCallsPerSecond, int? burstSize = null)
    {
        var opts = new SentinelOptions { MaxCallsPerSecond = maxCallsPerSecond, BurstSize = burstSize };
        var pipeline = new DetectionPipeline([], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        return new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);
    }

    [Fact]
    public async Task WithinBurst_Succeeds()
    {
        var sentinel = Build(maxCallsPerSecond: 10, burstSize: 3);
        for (var i = 0; i < 3; i++)
        {
            var result = await sentinel.GetResponseResultAsync(
                [new ChatMessage(ChatRole.User, "hi")], null, default);
            Assert.True(result.IsSuccess);
        }
    }

    [Fact]
    public async Task ExceedsBurst_ReturnsRateLimitExceeded()
    {
        var sentinel = Build(maxCallsPerSecond: 1, burstSize: 2);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, default);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, default);

        var result = await sentinel.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hi")], null, default);
        Assert.True(result.IsFailure);
        Assert.IsType<SentinelError.RateLimitExceeded>(result.Error);
    }

    [Fact]
    public async Task Disabled_NoLimiting()
    {
        var sentinel = Build(maxCallsPerSecond: null);
        for (var i = 0; i < 50; i++)
        {
            var result = await sentinel.GetResponseResultAsync(
                [new ChatMessage(ChatRole.User, "hi")], null, default);
            Assert.True(result.IsSuccess);
        }
    }

    [Fact]
    public async Task DifferentSessionKeys_IndependentBuckets()
    {
        var sentinel = Build(maxCallsPerSecond: 1, burstSize: 1);
        var opts1 = new ChatOptions();
        opts1.AdditionalProperties = new AdditionalPropertiesDictionary
        {
            ["sentinel.session_id"] = "session-A"
        };
        var opts2 = new ChatOptions();
        opts2.AdditionalProperties = new AdditionalPropertiesDictionary
        {
            ["sentinel.session_id"] = "session-B"
        };

        // Exhaust session-A bucket (burst = 1)
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts1, default);
        var resultA = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts1, default);
        Assert.IsType<SentinelError.RateLimitExceeded>(resultA.Error);

        // Session-B is independent — should succeed
        var resultB = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts2, default);
        Assert.True(resultB.IsSuccess);
    }

    private sealed class NoOpChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages,
            ChatOptions? options = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotSupportedException();

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
