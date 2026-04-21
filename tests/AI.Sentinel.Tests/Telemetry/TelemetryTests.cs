using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests.Telemetry;

public class TelemetryTests
{
    /// <summary>
    /// Verifies that calling GetResponseResultAsync produces "sentinel.scan" Activity spans
    /// owned by SentinelPipeline itself, and that the domain tags are written directly onto
    /// those spans (not on a parent). A root activity is used to isolate spans from
    /// parallel test runs via TraceId.
    /// </summary>
    [Fact]
    public async Task SentinelScan_EmitsActivitySpan()
    {
        var activities = new System.Collections.Concurrent.ConcurrentBag<Activity>();

        using var testSource = new ActivitySource("sentinel.test");
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => string.Equals(s.Name, "ai.sentinel", StringComparison.Ordinal)
                               || string.Equals(s.Name, "sentinel.test", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activities.Add,
        };
        ActivitySource.AddActivityListener(listener);

        var pipeline = BuildPipeline(new AlwaysCleanDetector());

        // Wrap in a root span so all child sentinel.scan spans share the same TraceId,
        // allowing isolation from parallel test runs.
        ActivityTraceId traceId;
        using (var root = testSource.StartActivity("test.root")!)
        {
            traceId = root.TraceId;
            _ = await pipeline.GetResponseResultAsync(
                [new ChatMessage(ChatRole.User, "hello")], null, default);
        }

        // Filter to only the sentinel.scan spans from this test's trace.
        var scans = activities
            .Where(a => string.Equals(a.OperationName, "sentinel.scan", StringComparison.Ordinal)
                     && a.TraceId == traceId)
            .ToList();

        // GetResponseResultAsync performs two scans (prompt + response).
        Assert.Equal(2, scans.Count);
        Assert.All(scans, scan =>
        {
            Assert.Equal("None", scan.GetTagItem("sentinel.severity")?.ToString());
            Assert.Equal("True", scan.GetTagItem("sentinel.is_clean")?.ToString());
        });
    }

    /// <summary>
    /// Verifies that SentinelPipeline increments the "sentinel.threats" counter with the
    /// correct severity and detector tags when a threat is detected.
    /// </summary>
    [Fact]
    public async Task ThreatDetected_IncrementsSentinelThreatsCounter()
    {
        string? capturedSeverity = null;
        string? capturedDetector = null;

        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (instrument, l) =>
        {
            if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal) &&
                string.Equals(instrument.Name, "sentinel.threats", StringComparison.Ordinal))
                l.EnableMeasurementEvents(instrument);
        };
        meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            var tagArray = tags.ToArray();
            capturedSeverity = tagArray.FirstOrDefault(t => string.Equals(t.Key, "severity", StringComparison.Ordinal)).Value?.ToString();
            capturedDetector = tagArray.FirstOrDefault(t => string.Equals(t.Key, "detector", StringComparison.Ordinal)).Value?.ToString();
        });
        meterListener.Start();

        var sentinel = BuildPipeline([new AlwaysCriticalDetector()]);

        _ = await sentinel.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "attack")], null, default);

        Assert.Equal("Critical", capturedSeverity);
        Assert.Equal("TEST-01", capturedDetector);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static SentinelPipeline BuildPipeline(IDetector detector)
        => BuildPipeline([detector]);

    private static SentinelPipeline BuildPipeline(IDetector[] detectors)
    {
        var opts = new SentinelOptions();
        IDetectionPipeline inner = new DetectionPipeline(detectors, null);
        var pipeline = new DetectionPipelineInstrumented(inner);
        IAuditStore innerAudit = new RingBufferAuditStore(100);
        var audit = new AuditStoreInstrumented(innerAudit);
        var engine = new InterventionEngine(opts, null);
        return new SentinelPipeline(new NoOpChatClient(), pipeline, audit, engine, opts);
    }

    private sealed class AlwaysCleanDetector : IDetector
    {
        public DetectorId Id => new("CLEAN-00");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.Clean(Id));
    }

    private sealed class AlwaysCriticalDetector : IDetector
    {
        public DetectorId Id => new("TEST-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "forced critical"));
    }

    private sealed class NoOpChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            CancellationToken ct = default)
            => throw new NotSupportedException();

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
