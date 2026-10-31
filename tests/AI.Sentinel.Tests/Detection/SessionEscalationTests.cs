using System.Collections.Concurrent;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>A detector marked <see cref="ISessionEscalatingDetector"/> goes up one level when the session already
/// holds <see cref="SessionHistory.EscalationThreshold"/> earlier hits of it.</summary>
public class SessionEscalationTests
{
    private const string Suffix = "; repeated in earlier scans of this session";
    private const string HighExample = "high-example phrase";
    private const string MediumExample = "medium-example phrase";
    private const string LowExample = "low-example phrase";

    [Fact]
    public async Task Escalation_TwoEarlierHits_RaisesOneLevel()
    {
        var lookup = new Lookup(2);

        var d = await RunSingleAsync(new FakeEscalatingDetector("TST-ESC", Severity.Low), lookup);

        Assert.Equal(Severity.Medium, d.Severity);
        Assert.Equal("fake" + Suffix, d.Reason);
        Assert.Equal([new DetectorId("TST-ESC")], lookup.Asked);
    }

    [Fact]
    public async Task Escalation_OneEarlierHit_NoChange()
    {
        var d = await RunSingleAsync(new FakeEscalatingDetector("TST-ESC", Severity.Low), new Lookup(1));

        Assert.Equal(Severity.Low, d.Severity);
        Assert.Equal("fake", d.Reason);
    }

    [Fact]
    public async Task Escalation_FiveEarlierHits_StillOneLevel()
    {
        var d = await RunSingleAsync(new FakeEscalatingDetector("TST-ESC", Severity.Low), new Lookup(5));

        Assert.Equal(Severity.Medium, d.Severity);
    }

    [Fact]
    public async Task Escalation_CleanResult_StaysClean_AndNoLookup()
    {
        var lookup = new Lookup(5);
        var pipeline = new DetectionPipeline([new FakeEscalatingDetector("TST-ESC", Severity.None)], null, reviewer: null);

        var result = await pipeline.RunAsync(Ctx(lookup.Count), TestContext.Current.CancellationToken);

        Assert.Empty(result.Detections);
        Assert.Empty(lookup.Asked);
    }

    [Fact]
    public async Task Escalation_UnmarkedDetector_NotEscalated_AndNoLookup()
    {
        var lookup = new Lookup(5);

        var d = await RunSingleAsync(new FakeDetector("TST-PLAIN", Severity.Low), lookup);

        Assert.Equal(Severity.Low, d.Severity);
        Assert.Equal("fake", d.Reason);
        Assert.Empty(lookup.Asked);
    }

    [Fact]
    public async Task Escalation_NullLookup_NoChange()
    {
        var pipeline = new DetectionPipeline([new FakeEscalatingDetector("TST-ESC", Severity.Low)], null, reviewer: null);

        var result = await pipeline.RunAsync(Ctx(earlierHits: null), TestContext.Current.CancellationToken);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Low, d.Severity);
        Assert.Equal("fake", d.Reason);
    }

    [Fact]
    public async Task Escalation_RespectsSeverityCap()
    {
        var configurations = new Dictionary<Type, DetectorConfiguration>
        {
            [typeof(FakeEscalatingDetector)] = new() { SeverityCap = Severity.Low },
        };

        var d = await RunSingleAsync(new FakeEscalatingDetector("TST-ESC", Severity.Low), new Lookup(2), configurations);

        Assert.Equal(Severity.Low, d.Severity);
        Assert.Equal("fake", d.Reason);
    }

    [Fact]
    public async Task Escalation_CriticalStaysCritical()
    {
        var d = await RunSingleAsync(new FakeEscalatingDetector("TST-ESC", Severity.Critical), new Lookup(2));

        Assert.Equal(Severity.Critical, d.Severity);
        Assert.Equal("fake", d.Reason);
    }

    [Fact]
    public async Task Escalation_SemanticMediumToHigh_CappedWithoutReviewer()
    {
        var d = await RunSemanticAsync(reviewer: null);

        Assert.Equal(Severity.Medium, d.Severity);
        Assert.StartsWith("Semantic match — capped at Medium pending review", d.Reason, StringComparison.Ordinal);
        Assert.EndsWith(Suffix, d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Escalation_SemanticMediumToHigh_ConfirmingReviewerReachesHigh()
    {
        var reviewer = new ConfirmingReviewer();

        var d = await RunSemanticAsync(reviewer);

        Assert.Equal(Severity.High, d.Severity);
        var request = Assert.Single(reviewer.Requests);
        Assert.Equal(Severity.High, request.ProposedSeverity);
        // The detector's reason, with the note, stays in front of the review's outcome.
        Assert.Equal("Semantic match — medium-severity threat pattern" + Suffix + " — Reviewed: confirmed — repeated drift", d.Reason);
    }

    [Fact]
    public void DriftDetectors_AreMarked()
    {
        // Every concrete detector in the library, official or internal, so no other one is marked by mistake.
        var marked = typeof(IDetector).Assembly.GetTypes()
            .Where(t => !t.IsAbstract && typeof(ISessionEscalatingDetector).IsAssignableFrom(t))
            .OrderBy(t => t.Name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal([typeof(IntraSessionContradictionDetector), typeof(PersonaDriftDetector)], marked);
        Assert.True(OfficialDetectors.TryResolve("OPS-13", out var ops13));
        Assert.True(OfficialDetectors.TryResolve("HAL-07", out var hal07));
        Assert.Equal(typeof(PersonaDriftDetector), ops13);
        Assert.Equal(typeof(IntraSessionContradictionDetector), hal07);
    }

    // ---- helpers ----

    private static SentinelContext Ctx(Func<DetectorId, CancellationToken, ValueTask<int>>? earlierHits, string text = "scanned") =>
        new(new AgentId("a"), new AgentId("b"), SessionId.New(), [new ChatMessage(ChatRole.User, text)], new List<AuditEntry>())
        {
            EarlierHits = earlierHits,
        };

    private static async Task<DetectionResult> RunSingleAsync(
        IDetector detector, Lookup lookup, IReadOnlyDictionary<Type, DetectorConfiguration>? configurations = null)
    {
        var pipeline = new DetectionPipeline([detector], configurations, reviewer: null);
        var result = await pipeline.RunAsync(Ctx(lookup.Count), TestContext.Current.CancellationToken);
        return Assert.Single(result.Detections);
    }

    /// <summary>A Medium-bucket hit of a marked semantic detector with two earlier hits, built like the semantic-cap tests.</summary>
    private static async Task<DetectionResult> RunSemanticAsync(IDetectionReviewer? reviewer)
    {
        var options = new SentinelOptions { EmbeddingGenerator = new ExactMatchEmbeddingGenerator() };
        var pipeline = new DetectionPipeline(
            [new EscalatingSemanticDetector(options)], configurations: null, reviewer: reviewer,
            embeddingScope: new EmbeddingScope(options.EmbeddingGenerator!, new InMemoryLruEmbeddingCache(), null));
        var result = await pipeline.RunAsync(Ctx(new Lookup(2).Count, MediumExample), TestContext.Current.CancellationToken);
        return Assert.Single(result.Detections);
    }

    /// <summary>Answers a fixed count and records the ids it was asked about.</summary>
    private sealed class Lookup(int count)
    {
        public ConcurrentQueue<DetectorId> Asked { get; } = new();

        public ValueTask<int> Count(DetectorId id, CancellationToken ct)
        {
            Asked.Enqueue(id);
            return ValueTask.FromResult(count);
        }
    }

    private sealed class FakeDetector(string id, Severity severity) : IDetector
    {
        public DetectorId Id { get; } = new(id);
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(Id)
                : DetectionResult.WithSeverity(Id, severity, "fake"));
    }

    private sealed class FakeEscalatingDetector(string id, Severity severity) : ISessionEscalatingDetector
    {
        public DetectorId Id { get; } = new(id);
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(Id)
                : DetectionResult.WithSeverity(Id, severity, "fake"));
    }

    /// <summary>Maps each bucket to its own severity, so a Medium-bucket hit is Medium before escalation.</summary>
    private sealed class EscalatingSemanticDetector(SentinelOptions options) : SemanticDetectorBase(options), ISessionEscalatingDetector
    {
        protected override string ReviewCriterion => "A test-only detector with a generic criterion, never reviewed by a real judge.";
        public override DetectorId Id => new("TST-DRIFT");
        public override DetectorCategory Category => DetectorCategory.Operational;
        protected override string[] HighExamples => [HighExample];
        protected override string[] MediumExamples => [MediumExample];
        protected override string[] LowExamples => [LowExample];
    }

    /// <summary>Confirms the proposed severity of every request it receives.</summary>
    private sealed class ConfirmingReviewer : IDetectionReviewer
    {
        public ConcurrentQueue<ReviewRequest> Requests { get; } = new();

        public ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken)
        {
            Requests.Enqueue(request);
            return ValueTask.FromResult(new ReviewVerdict(request.ProposedSeverity, "repeated drift"));
        }
    }
}
