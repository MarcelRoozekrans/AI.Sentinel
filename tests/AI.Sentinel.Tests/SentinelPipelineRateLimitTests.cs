using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
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

    [Fact]
    public async Task ExceedsLimit_EmitsMetric()
    {
        var measurements = new ConcurrentBag<(string Name, string? Session)>();
        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (instrument, l) =>
        {
            if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal) &&
                string.Equals(instrument.Name, "sentinel.rate_limit.exceeded", StringComparison.Ordinal))
                l.EnableMeasurementEvents(instrument);
        };
        meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            var session = tags.ToArray()
                .FirstOrDefault(t => string.Equals(t.Key, "session", StringComparison.Ordinal)).Value?.ToString();
            measurements.Add((instrument.Name, session));
        });
        meterListener.Start();

        var sentinel = Build(maxCallsPerSecond: 1, burstSize: 1);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, default);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, default);

        Assert.Contains(measurements, m =>
            string.Equals(m.Name, "sentinel.rate_limit.exceeded", StringComparison.Ordinal) &&
            string.Equals(m.Session, "__global__", StringComparison.Ordinal));
    }

    [Fact]
    public async Task IdleSession_LimiterEvicted_BurstRestored()
    {
        var opts = new SentinelOptions
        {
            MaxCallsPerSecond = 1,
            BurstSize = 1,
            SessionIdleTimeout = TimeSpan.FromMilliseconds(50)
        };
        var pipeline = new DetectionPipeline([], null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        var sentinel = new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);

        var optsA = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = "session-A" } };

        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, default);
        var exhausted = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, default);
        Assert.IsType<SentinelError.RateLimitExceeded>(exhausted.Error);

        await Task.Delay(100);

        for (var i = 0; i < 256; i++)
        {
            var sweepOpts = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = $"sweep-{i}" } };
            _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], sweepOpts, default);
        }

        var restored = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, default);
        Assert.True(restored.IsSuccess);
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
