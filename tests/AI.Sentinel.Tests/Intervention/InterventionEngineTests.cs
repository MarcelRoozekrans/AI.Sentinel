using Xunit;
using AI.Sentinel;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using ZeroAlloc.Mediator;

public class InterventionEngineTests
{
    private static PipelineResult CleanResult() =>
        new(ThreatRiskScore.Zero, new List<DetectionResult>());

    private static PipelineResult CriticalResult() =>
        new(new ThreatRiskScore(90),
            new List<DetectionResult> {
                DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.Critical, "injection")
            });

    [Fact] public void CleanResult_DoesNotThrow()
    {
        var opts = new SentinelOptions();
        var engine = new InterventionEngine(opts, mediator: null);
        engine.Apply(CleanResult());
    }

    [Fact] public void CriticalResult_WithQuarantineAction_Throws()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Quarantine };
        var engine = new InterventionEngine(opts, mediator: null);
        Assert.Throws<SentinelException>(() => engine.Apply(CriticalResult()));
    }

    [Fact] public void CriticalResult_WithLogAction_DoesNotThrow()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Log };
        var engine = new InterventionEngine(opts, mediator: null);
        engine.Apply(CriticalResult());
    }

    [Fact]
    public void Apply_WithMediator_PublishesTwoNotifications()
    {
        var published = new List<object>();
        var mediator = new RecordingMediator(published);
        var opts = new SentinelOptions { OnCritical = SentinelAction.Log };
        var engine = new InterventionEngine(opts, mediator);

        engine.Apply(CriticalResult());

        Assert.Equal(2, published.Count);
    }

    [Fact]
    public void Apply_WithPassThrough_DoesNotPublish()
    {
        var published = new List<object>();
        var mediator = new RecordingMediator(published);
        var opts = new SentinelOptions
        {
            OnCritical = SentinelAction.PassThrough,
            OnHigh = SentinelAction.PassThrough,
            OnMedium = SentinelAction.PassThrough,
            OnLow = SentinelAction.PassThrough
        };
        var engine = new InterventionEngine(opts, mediator);

        engine.Apply(CriticalResult());

        Assert.Empty(published);
    }

    [Fact]
    public void Apply_WhenMediatorThrows_DoesNotPropagateException()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Log };
        var engine = new InterventionEngine(opts, new ThrowingMediator());

        // Should not throw — mediator failures must not crash the detection pipeline
        engine.Apply(CriticalResult());
    }

    private sealed class RecordingMediator(List<object> published) : IMediator
    {
        public ValueTask Publish<TNotification>(TNotification notification, CancellationToken ct = default)
            where TNotification : INotification
        {
            published.Add(notification!);
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task Apply_WhenMediatorFaultsAsync_DoesNotPropagate()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Log };
        var engine = new InterventionEngine(opts, new AsyncFaultingMediator());

        // Must not throw synchronously
        engine.Apply(CriticalResult());

        // Give the async continuation time to complete
        await Task.Delay(100);
        // No assertion needed beyond "did not throw" — the test verifies the async fault
        // path (ContinueWith) is reached without crashing the caller
    }

    private sealed class ThrowingMediator : IMediator
    {
        public ValueTask Publish<TNotification>(TNotification notification, CancellationToken ct = default)
            where TNotification : INotification
            => ValueTask.FromException(new InvalidOperationException("mediator failure"));
    }

    private sealed class AsyncFaultingMediator : IMediator
    {
        public ValueTask Publish<TNotification>(TNotification notification, CancellationToken ct = default)
            where TNotification : INotification
            => new ValueTask(Task.Run(async () =>
            {
                await Task.Yield();
                throw new InvalidOperationException("async mediator fault");
            }));
    }
}
