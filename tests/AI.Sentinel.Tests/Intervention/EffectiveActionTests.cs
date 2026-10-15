using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZeroAlloc.Mediator;

namespace AI.Sentinel.Tests.Intervention;

public class EffectiveActionTests
{
    private sealed class FixedDetector(string id, Severity severity, SentinelAction? actionOverride = null) : IDetector
    {
        private readonly DetectorId _id = new(id);
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, "stub") with { ActionOverride = actionOverride });
    }

    private sealed class FakeRedactingDetector(Severity severity) : IRedactingDetector
    {
        private readonly DetectorId _id = new("RED-01");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, "stub"));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) => [];
    }

    private sealed class NoopChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotSupportedException();
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken ct = default)
            => throw new NotSupportedException();
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
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

    private static PipelineResult Result(params DetectionResult[] detections) =>
        new(new ThreatRiskScore(50), detections);

    private static DetectionResult Det(Severity s, SentinelAction? over = null) =>
        DetectionResult.WithSeverity(new DetectorId("X-01"), s, "stub") with { ActionOverride = over };

    private static List<InterventionAppliedNotification> Applied(List<object> published) =>
        published.OfType<InterventionAppliedNotification>().ToList();

    [Fact]
    public void Override_Quarantine_BeatsSeverityLog()
    {
        var engine = new InterventionEngine(new SentinelOptions(), mediator: null);
        Assert.Throws<SentinelException>(() =>
            engine.Apply(Result(Det(Severity.Low, SentinelAction.Quarantine))));
    }

    [Fact]
    public void Override_Log_LowersCritical()
    {
        var published = new List<object>();
        var engine = new InterventionEngine(new SentinelOptions(), new RecordingMediator(published));
        engine.Apply(Result(Det(Severity.Critical, SentinelAction.Log)));
        Assert.Equal(SentinelAction.Log, Assert.Single(Applied(published)).Action);
    }

    [Fact]
    public void MixedDetections_MostRestrictiveWins()
    {
        var published = new List<object>();
        var engine = new InterventionEngine(new SentinelOptions(), new RecordingMediator(published));
        engine.Apply(Result(Det(Severity.Low, SentinelAction.Alert), Det(Severity.Low, SentinelAction.Log)));
        Assert.Equal(SentinelAction.Alert, Assert.Single(Applied(published)).Action);
    }

    [Fact]
    public void RedactOverride_InScan_FallsBackToSeverityAction()
    {
        var published = new List<object>();
        var opts = new SentinelOptions { OnHigh = SentinelAction.Alert };
        var engine = new InterventionEngine(opts, new RecordingMediator(published));
        engine.Apply(Result(Det(Severity.High, SentinelAction.Redact)));
        Assert.Equal(SentinelAction.Alert, Assert.Single(Applied(published)).Action);
    }

    [Fact]
    public async Task RedactOverride_InScan_AuditSummaryEndsWithNotRedacted()
    {
        var opts = new SentinelOptions();
        var pipeline = new DetectionPipeline(
            [new FixedDetector("X-01", Severity.High, SentinelAction.Redact), new FixedDetector("X-02", Severity.High)],
            configurations: null, escalationClient: null);
        var audit = new RingBufferAuditStore(100);
        var sp = new SentinelPipeline(new NoopChatClient(), pipeline, audit,
            new InterventionEngine(opts, null), opts);

        _ = await sp.ScanMessagesAsync([new ChatMessage(ChatRole.User, "hello")],
            ct: TestContext.Current.CancellationToken);

        var entries = new List<AuditEntry>();
        await foreach (var e in audit.QueryAsync(new AuditQuery(), TestContext.Current.CancellationToken))
            entries.Add(e);
        Assert.Equal(2, entries.Count);
        Assert.EndsWith("; not redacted", entries.Single(e => string.Equals(e.DetectorId, "X-01", StringComparison.Ordinal)).Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("not redacted", entries.Single(e => string.Equals(e.DetectorId, "X-02", StringComparison.Ordinal)).Summary, StringComparison.Ordinal);
    }

    private static async Task<DetectionResult> RunOne(IDetector detector, bool redactByDefault, SentinelOptions? opts = null)
    {
        var pipeline = new DetectionPipeline(
            [detector], opts?.GetDetectorConfigurations(), escalationClient: null,
            redactByDefault: redactByDefault);
        var ctx = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(), [], []);
        var r = await pipeline.RunAsync(ctx, TestContext.Current.CancellationToken);
        return Assert.Single(r.Detections);
    }

    [Fact]
    public async Task RedactByDefault_SetsOverrideOnRedactingDetectorsOnly()
    {
        var redacting = await RunOne(new FakeRedactingDetector(Severity.High), redactByDefault: true);
        var plain = await RunOne(new FixedDetector("X-01", Severity.High), redactByDefault: true);
        Assert.Equal(SentinelAction.Redact, redacting.ActionOverride);
        Assert.Null(plain.ActionOverride);
    }

    [Fact]
    public async Task RedactByDefaultFalse_LeavesOverrideNull()
    {
        var r = await RunOne(new FakeRedactingDetector(Severity.High), redactByDefault: false);
        Assert.Null(r.ActionOverride);
    }

    [Fact]
    public async Task ConfiguredAction_WinsOverRedactByDefault()
    {
        var opts = new SentinelOptions();
        opts.Configure<FakeRedactingDetector>(c => c.Action = SentinelAction.Quarantine);
        var r = await RunOne(new FakeRedactingDetector(Severity.High), redactByDefault: true, opts);
        Assert.Equal(SentinelAction.Quarantine, r.ActionOverride);
    }

    [Fact]
    public void SeverityOption_SetToRedact_ThrowsOnAddAISentinel()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new ServiceCollection().AddAISentinel(o => o.OnHigh = SentinelAction.Redact));
        Assert.Contains("OnHigh", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactConfigured_OnNonRedactingDetector_ThrowsWhenPipelineBuilds()
    {
        var opts = new SentinelOptions();
        opts.Configure<FixedDetector>(c => c.Action = SentinelAction.Redact);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new DetectionPipeline([new FixedDetector("X-01", Severity.High)],
                opts.GetDetectorConfigurations(), escalationClient: null));
        Assert.Contains(nameof(FixedDetector), ex.Message, StringComparison.Ordinal);
    }
}
