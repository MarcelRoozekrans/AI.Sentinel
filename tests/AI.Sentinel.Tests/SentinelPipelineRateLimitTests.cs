using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Redaction;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelPipelineRateLimitTests
{
    private static SentinelPipeline Build(int? maxCallsPerSecond, int? burstSize = null)
    {
        var opts = new SentinelOptions { MaxCallsPerSecond = maxCallsPerSecond, BurstSize = burstSize };
        var pipeline = new DetectionPipeline([], configurations: null, escalationClient: null);
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
                [new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);
            Assert.True(result.IsSuccess);
        }
    }

    [Fact]
    public async Task ExceedsBurst_ReturnsRateLimitExceeded()
    {
        var sentinel = Build(maxCallsPerSecond: 1, burstSize: 2);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);

        var result = await sentinel.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);
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
                [new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);
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
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts1, TestContext.Current.CancellationToken);
        var resultA = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts1, TestContext.Current.CancellationToken);
        Assert.IsType<SentinelError.RateLimitExceeded>(resultA.Error);

        // Session-B is independent — should succeed
        var resultB = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], opts2, TestContext.Current.CancellationToken);
        Assert.True(resultB.IsSuccess);
    }

    [Fact]
    public async Task RateLimit_KeysOnConversationId()
    {
        var sentinel = Build(maxCallsPerSecond: 1, burstSize: 1);
        var a = new ChatOptions { ConversationId = "a" };
        var b = new ChatOptions { ConversationId = "b" };

        var first = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], a, TestContext.Current.CancellationToken);
        var second = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], a, TestContext.Current.CancellationToken);
        var third = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], b, TestContext.Current.CancellationToken);

        Assert.True(first.IsSuccess);
        Assert.IsType<SentinelError.RateLimitExceeded>(second.Error);
        Assert.True(third.IsSuccess);
    }

    // Ruling 1: a host path keeps the shared __global__ key even when it names a session, with or without a redactor.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RedactAndScan_LimitsOnGlobalKey_NotOnTheSession(bool withRedactor)
    {
        var opts = new SentinelOptions { MaxCallsPerSecond = 1, BurstSize = 1 };
        IDetector[] detectors = withRedactor ? [new PiiLeakageDetector()] : [];
        var sentinel = new SentinelPipeline(new NoOpChatClient(),
            new DetectionPipeline(detectors, configurations: null, escalationClient: null),
            new RingBufferAuditStore(100), new InterventionEngine(opts, null), opts);
        var request = new HostRedactionRequest { Content = [HostContent.FromText("hi")] };

        var first = await sentinel.RedactAndScanAsync(request, new SessionId("host-a"), TestContext.Current.CancellationToken);
        var second = await sentinel.RedactAndScanAsync(request, new SessionId("host-b"), TestContext.Current.CancellationToken);

        Assert.Null(first.Error);
        Assert.Equal(new SentinelError.RateLimitExceeded("__global__"), second.Error);
    }

    [Fact]
    public async Task ScanMessages_LimitsOnConversationId()
    {
        var sentinel = Build(maxCallsPerSecond: 1, burstSize: 1);
        var a = new ChatOptions { ConversationId = "a" };
        var b = new ChatOptions { ConversationId = "b" };

        var first = await sentinel.ScanMessagesAsync([new ChatMessage(ChatRole.User, "hi")], a, ct: TestContext.Current.CancellationToken);
        var second = await sentinel.ScanMessagesAsync([new ChatMessage(ChatRole.User, "hi")], a, ct: TestContext.Current.CancellationToken);
        var third = await sentinel.ScanMessagesAsync([new ChatMessage(ChatRole.User, "hi")], b, ct: TestContext.Current.CancellationToken);

        Assert.Null(first);
        Assert.Equal(new SentinelError.RateLimitExceeded("a"), second);
        Assert.Null(third);
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
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);
        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);

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
        var pipeline = new DetectionPipeline([], configurations: null, escalationClient: null);
        var audit = new RingBufferAuditStore(100);
        var engine = new InterventionEngine(opts, null);
        var sentinel = new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);

        var optsA = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = "session-A" } };

        _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, TestContext.Current.CancellationToken);
        var exhausted = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, TestContext.Current.CancellationToken);
        Assert.IsType<SentinelError.RateLimitExceeded>(exhausted.Error);

        await Task.Delay(100, TestContext.Current.CancellationToken);

        for (var i = 0; i < 256; i++)
        {
            var sweepOpts = new ChatOptions { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = $"sweep-{i}" } };
            _ = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], sweepOpts, TestContext.Current.CancellationToken);
        }

        var restored = await sentinel.GetResponseResultAsync([new ChatMessage(ChatRole.User, "hi")], optsA, TestContext.Current.CancellationToken);
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
