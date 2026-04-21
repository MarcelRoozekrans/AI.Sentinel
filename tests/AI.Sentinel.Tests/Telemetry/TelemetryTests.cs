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
    /// Verifies that calling GetResponseResultAsync produces a "sentinel.scan" Activity span
    /// and enriches the ambient Activity with domain tags when the message is clean.
    ///
    /// DetectionPipelineInstrumented (source-generated proxy) opens a child span named
    /// "sentinel.scan" around RunAsync. After RunAsync returns the span is stopped, so
    /// SentinelPipeline.ScanAsync sets the domain tags on Activity.Current — which, inside
    /// a test-created parent span, is that parent span. The test therefore:
    ///   1. Asserts that a "sentinel.scan" child Activity was emitted.
    ///   2. Asserts that the parent span received the "sentinel.severity" and
    ///      "sentinel.is_clean" domain tags.
    /// </summary>
    [Fact]
    public async Task SentinelScan_EmitsActivitySpan()
    {
        var collectedActivities = new List<Activity>();

        using var testSource = new ActivitySource("sentinel.test");
        using var listener = new ActivityListener
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, "ai.sentinel", StringComparison.Ordinal) ||
                string.Equals(source.Name, "sentinel.test", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => collectedActivities.Add(activity),
        };
        ActivitySource.AddActivityListener(listener);

        var sentinel = BuildPipeline(detectors: []);

        // Wrap in a parent span so Activity.Current is non-null when ScanAsync sets tags.
        using (testSource.StartActivity("test.request"))
        {
            _ = await sentinel.GetResponseResultAsync(
                [new ChatMessage(ChatRole.User, "Hello")], null, default);
        }

        // The sentinel.scan child span must have been emitted.
        var scan = collectedActivities.FirstOrDefault(
            a => string.Equals(a.OperationName, "sentinel.scan", StringComparison.Ordinal));
        Assert.NotNull(scan);

        // Domain tags are written to Activity.Current (the parent span) by ScanAsync.
        var parent = collectedActivities.FirstOrDefault(
            a => string.Equals(a.OperationName, "test.request", StringComparison.Ordinal));
        Assert.NotNull(parent);
        // MaxSeverity is Severity.None when no detectors fire; IsClean == true.
        Assert.Equal("None", parent.GetTagItem("sentinel.severity")?.ToString());
        Assert.Equal("True", parent.GetTagItem("sentinel.is_clean")?.ToString());
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
