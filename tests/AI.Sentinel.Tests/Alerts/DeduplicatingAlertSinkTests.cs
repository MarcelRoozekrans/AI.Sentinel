using AI.Sentinel.Alerts;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using System.Diagnostics.Metrics;
using Xunit;

namespace AI.Sentinel.Tests.Alerts;

public class DeduplicatingAlertSinkTests
{
    private static SentinelError.ThreatDetected MakeThreat(string detectorId, SessionId sessionId) =>
        new(DetectionResult.WithSeverity(new DetectorId(detectorId), Severity.High, "test"),
            SentinelAction.Alert,
            sessionId);

    [Fact]
    public async Task SameDetectorSameSession_SecondAlert_IsSuppressed()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);
        var session = SessionId.New();
        var threat = MakeThreat("SEC-01", session);

        await sink.SendAsync(threat, default);
        await sink.SendAsync(threat, default);

        Assert.Equal(1, inner.CallCount);
    }

    [Fact]
    public async Task SameDetectorDifferentSession_BothAlerts_PassThrough()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);

        await sink.SendAsync(MakeThreat("SEC-01", SessionId.New()), default);
        await sink.SendAsync(MakeThreat("SEC-01", SessionId.New()), default);

        Assert.Equal(2, inner.CallCount);
    }

    [Fact]
    public async Task TimeWindow_AfterExpiry_AlertPassesThrough()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner, window: TimeSpan.FromMilliseconds(100));
        var session = SessionId.New();

        await sink.SendAsync(MakeThreat("SEC-01", session), default);
        await Task.Delay(300); // wait for window to expire
        await sink.SendAsync(MakeThreat("SEC-01", session), default);

        Assert.Equal(2, inner.CallCount);
    }

    [Fact]
    public async Task PipelineFailure_NeverSuppressed()
    {
        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);
        var failure = new SentinelError.PipelineFailure("test error");

        await sink.SendAsync(failure, default);
        await sink.SendAsync(failure, default);

        Assert.Equal(2, inner.CallCount);
    }

    [Fact]
    public async Task SuppressedAlert_IncrementsCounter()
    {
        var measurements = new List<long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal) &&
                string.Equals(instrument.Name, "sentinel.alerts.suppressed", StringComparison.Ordinal))
                l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => measurements.Add(val));
        listener.Start();

        var inner = new RecordingAlertSink();
        var sink = new DeduplicatingAlertSink(inner);
        var session = SessionId.New();

        await sink.SendAsync(MakeThreat("SEC-01", session), default);
        await sink.SendAsync(MakeThreat("SEC-01", session), default); // suppressed

        Assert.Single(measurements);
        Assert.Equal(1L, measurements[0]);
    }

    private sealed class RecordingAlertSink : IAlertSink
    {
        private int _callCount;
        public int CallCount => _callCount;

        public ValueTask SendAsync(SentinelError error, CancellationToken ct)
        {
            Interlocked.Increment(ref _callCount);
            return ValueTask.CompletedTask;
        }
    }
}
