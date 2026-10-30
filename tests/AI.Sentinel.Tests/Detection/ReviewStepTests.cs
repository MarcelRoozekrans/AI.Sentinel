using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text.RegularExpressions;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>The pipeline's review step: which detections go to the <see cref="IDetectionReviewer"/>, in which order and
/// under which budget and timeout, and how a verdict changes the result.</summary>
public class ReviewStepTests
{
    private const string HighExample = "high-example";
    private const string MediumExample = "medium-example";
    private const string LowExample = "low-example";
    private const string FastPathText = "FASTPATH-TRIGGER";
    private const string TestCriterion = "A test-only detector with a generic criterion, never reviewed by a real judge.";

    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    // ---- verdicts ----

    [Fact]
    public async Task Review_ConfirmsHighBucket_LiftsCapToBucketSeverity()
    {
        // SEC-01-style: the Medium bucket maps to High, which the cap shows as Medium until a reviewer confirms it.
        var detector = Semantic("REV-CONFIRM", Vector(Axis.Medium, 0.85f), mapped: true);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.High, "clear override"));

        var result = await RunAsync([detector], reviewer);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.High, d.Severity);
        Assert.Equal("Reviewed: confirmed — clear override", d.Reason);
        var request = Assert.Single(reviewer.Requests);
        Assert.Equal(new DetectorId("REV-CONFIRM"), request.DetectorId);
        Assert.Equal(TestCriterion, request.Criterion);
        Assert.Equal(ScanText, request.Text);
        Assert.Equal(ChatRole.User, request.Role);
        Assert.Equal(0.85f, request.Score!.Value, 0.001f);
        Assert.Equal(Severity.High, request.ProposedSeverity);
        Assert.Equal(Severity.Critical, request.MaximumSeverity);
    }

    [Fact]
    public async Task Review_RaisesBandCandidate_ToMedium()
    {
        // 0.7 reaches no bucket, but it is above the review threshold of 0.6.
        var detector = Semantic("REV-BAND", Vector(Axis.Medium, 0.7f), reviewThreshold: 0.6f);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Medium, "paraphrased override"));

        var result = await RunAsync([detector], reviewer);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Medium, d.Severity);
        Assert.Equal("Reviewed: raised — paraphrased override", d.Reason);
        var request = Assert.Single(reviewer.Requests);
        Assert.Equal(Severity.None, request.ProposedSeverity);
        Assert.Equal(Severity.High, request.MaximumSeverity);
        Assert.Equal(0.7f, request.Score!.Value, 0.001f);
    }

    [Fact]
    public async Task Review_LowBucketBelowReviewThreshold_NotACandidate()
    {
        // A Low bucket hit at 0.76, with a review threshold of 0.8 above it, stays Low and unreviewed.
        var detector = Semantic("REV-LOWNOT", Vector(Axis.Low, 0.76f), reviewThreshold: 0.8f);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.High, "x"));

        var result = await RunAsync([detector], reviewer);

        Assert.Equal(Severity.Low, Assert.Single(result.Detections).Severity);
        Assert.Empty(reviewer.Requests);
    }

    [Fact]
    public async Task Review_VerdictAboveMaximum_IsClamped()
    {
        // Default bucket mapping: the highest severity this detector reports is High.
        var detector = Semantic("REV-CLAMP", Vector(Axis.Medium, 0.7f), reviewThreshold: 0.6f);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Critical, "x"));

        var result = await RunAsync([detector], reviewer);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.High, d.Severity);
        Assert.StartsWith("Reviewed: raised", d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Review_None_Clears()
    {
        var detector = Semantic("REV-NONE", Vector(Axis.High, 0.95f));
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.None, "this is not Critical"));

        var result = await RunAsync([detector], reviewer);

        Assert.Empty(result.Detections);
    }

    [Fact]
    public async Task Review_NullVerdict_KeepsCappedResult()
    {
        var detector = Semantic("REV-NULL", Vector(Axis.Medium, 0.85f), mapped: true);
        var reviewer = new FakeReviewer((_, _) => ReviewVerdict.None);

        var result = await RunAsync([detector], reviewer);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Medium, d.Severity);
        Assert.Equal("Semantic match — capped at Medium pending review", d.Reason);
    }

    [Fact]
    public async Task Review_FastPathMatch_NotSentToReviewer()
    {
        var detector = Semantic("REV-FAST", Vector(Axis.High, 0.95f), mapped: true, text: FastPathText);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.None, "x"));

        var result = await RunAsync([detector], reviewer, Ctx(new ChatMessage(ChatRole.User, FastPathText)));

        Assert.Equal(Severity.Critical, Assert.Single(result.Detections).Severity);
        Assert.Empty(reviewer.Requests);
    }

    [Fact]
    public async Task Review_RuleBasedEscalatingDetector_UsesNewestMessageAndCriterion()
    {
        // #434: when the newest message is a tool result, the reviewer is shown that result, not an empty text.
        var detector = new FakeEscalatingDetector("REV-RULE", Severity.Medium);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Medium, "confirmed"));
        var ctx = Ctx(
            new ChatMessage(ChatRole.User, "please read the file"),
            new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", "the tool said this")]));

        var result = await RunAsync([detector], reviewer, ctx);

        var request = Assert.Single(reviewer.Requests);
        Assert.Equal("the tool said this", request.Text);
        Assert.Equal(ChatRole.Tool, request.Role);
        Assert.Equal(FakeEscalatingDetector.Criterion, request.Criterion);
        Assert.Null(request.Score);
        Assert.Equal(Severity.Medium, request.ProposedSeverity);
        Assert.Equal(Severity.Critical, request.MaximumSeverity);
        Assert.Equal("Reviewed: confirmed — confirmed", Assert.Single(result.Detections).Reason);
    }

    [Fact]
    public async Task Review_RuleBasedBelowMedium_NotACandidate()
    {
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.High, "x"));

        var result = await RunAsync([new FakeEscalatingDetector("REV-RULELOW", Severity.Low)], reviewer);

        Assert.Equal(Severity.Low, Assert.Single(result.Detections).Severity);
        Assert.Empty(reviewer.Requests);
    }

    [Fact]
    public async Task Review_VerdictLow_LowersTheSeverity()
    {
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Low, "benign"));

        var result = await RunAsync([new FakeEscalatingDetector("REV-LOWER", Severity.High)], reviewer);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Low, d.Severity);
        Assert.Equal("Reviewed: lowered — benign", d.Reason);
    }

    [Fact]
    public async Task Review_VerdictAboveTheConfiguredCap_IsCapped()
    {
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Critical, "x"));
        var configurations = Config<FakeEscalatingDetector>(c => c.SeverityCap = Severity.High);

        var result = await RunAsync([new FakeEscalatingDetector("REV-CAP", Severity.Medium)], reviewer, configurations: configurations);

        Assert.Equal(Severity.High, Assert.Single(result.Detections).Severity);
        Assert.Equal(Severity.High, Assert.Single(reviewer.Requests).MaximumSeverity);
    }

    [Fact]
    public async Task Review_VerdictBelowTheConfiguredFloor_IsRaisedToTheFloor()
    {
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Low, "x"));
        var configurations = Config<FakeEscalatingDetector>(c => c.SeverityFloor = Severity.High);

        var result = await RunAsync([new FakeEscalatingDetector("REV-FLOOR", Severity.Medium)], reviewer, configurations: configurations);

        Assert.Equal(Severity.High, Assert.Single(result.Detections).Severity);
    }

    [Fact]
    public async Task Review_ActionOverride_SurvivesReview()
    {
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Critical, "x"));
        var configurations = Config<FakeEscalatingDetector>(c => c.Action = SentinelAction.Alert);

        var result = await RunAsync([new FakeEscalatingDetector("REV-ACTION", Severity.Medium)], reviewer, configurations: configurations);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Critical, d.Severity);   // the review really rebuilt the result
        Assert.Equal(SentinelAction.Alert, d.ActionOverride);
    }

    [Fact]
    public async Task Review_WithLlmJudgeReviewer_ReachesTheJudgeAndAppliesItsVerdict()
    {
        var captured = new List<ChatMessage>();
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient(captured, """{"severity":"High","reason":"clear override"}"""));
        var pipeline = new DetectionPipeline([new FakeEscalatingDetector("REV-JUDGE", Severity.Medium)], configurations: null, reviewer: reviewer);

        var result = await pipeline.RunAsync(Ctx(new ChatMessage(ChatRole.User, ScanText)), TestContext.Current.CancellationToken);

        Assert.Equal(Severity.High, Assert.Single(result.Detections).Severity);
        Assert.Contains("REV-JUDGE", Assert.Single(captured, m => m.Role == ChatRole.System).Text, StringComparison.Ordinal);
    }

    // ---- budget and ranking ----

    [Fact]
    public async Task Review_BudgetOfTwo_ReviewsTopTwoByRanking_RestOverBudget()
    {
        using var metrics = new ReviewMetrics();
        var detectors = new IDetector[]
        {
            Semantic("BUD-MEDIUM", Vector(Axis.Medium, 0.85f)),            // Medium
            Semantic("BUD-HIGH", Vector(Axis.High, 0.95f)),                // High
            Semantic("BUD-LOW", Vector(Axis.Low, 0.78f)),                  // Low
            new FakeEscalatingDetector("BUD-CRITICAL", Severity.Critical), // Critical
        };
        var reviewer = new FakeReviewer((_, _) => ReviewVerdict.None);

        await RunAsync(detectors, reviewer, limits: new ReviewLimits(2, Generous));

        Assert.Equal(new[] { "BUD-CRITICAL", "BUD-HIGH" }, reviewer.Requests.Select(r => r.DetectorId.Value).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.Equal(2, metrics.Count("over_budget", "BUD-"));
        Assert.Equal(1, metrics.Count("over_budget", "BUD-MEDIUM"));
        Assert.Equal(1, metrics.Count("over_budget", "BUD-LOW"));
        Assert.Equal(2, metrics.Count("no_verdict", "BUD-"));
    }

    [Fact]
    public async Task Review_Ranking_RuleBasedBeforeSemanticAtEqualSeverity_ThenHigherScore()
    {
        var detectors = new IDetector[]
        {
            Semantic("RANK-SEM-LOWER", Vector(Axis.Medium, 0.83f)),
            Semantic("RANK-SEM-HIGHER", Vector(Axis.Medium, 0.88f)),
            new FakeEscalatingDetector("RANK-RULE", Severity.Medium),
        };
        var reviewer = new FakeReviewer((_, _) => ReviewVerdict.None);

        await RunAsync(detectors, reviewer, limits: new ReviewLimits(2, Generous));

        Assert.Equal(new[] { "RANK-RULE", "RANK-SEM-HIGHER" }, reviewer.Requests.Select(r => r.DetectorId.Value).Order(StringComparer.Ordinal), StringComparer.Ordinal);
    }

    [Fact]
    public async Task Review_MaxPerScanZero_NoReviews()
    {
        using var metrics = new ReviewMetrics();
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.High, "x"));

        var result = await RunAsync(
            [Semantic("ZERO-SEM", Vector(Axis.Medium, 0.85f), mapped: true)], reviewer, limits: new ReviewLimits(0, Generous));

        Assert.Equal(Severity.Medium, Assert.Single(result.Detections).Severity);
        Assert.Empty(reviewer.Requests);
        Assert.Equal(0, metrics.Count(outcome: null, "ZERO-"));
    }

    [Fact]
    public async Task Review_EachOutcome_IsCounted()
    {
        using var metrics = new ReviewMetrics();
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.High, "x"));

        await RunAsync([Semantic("CNT-CONFIRM", Vector(Axis.Medium, 0.85f), mapped: true)], reviewer);

        Assert.Equal(1, metrics.Count("confirmed", "CNT-CONFIRM"));
    }

    // ---- execution: concurrency, timeouts, failures, cancellation ----

    [Fact]
    public async Task Review_RunsConcurrently()
    {
        var bothStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = 0;
        var reviewer = new FakeReviewer(async (_, _) =>
        {
            if (Interlocked.Increment(ref started) == 2) bothStarted.SetResult();
            await bothStarted.Task;
            return new ReviewVerdict(Severity.High, "x");
        });

        var result = await RunAsync(
            [new FakeEscalatingDetector("CONC-A", Severity.Medium), new FakeEscalatingDetector("CONC-B", Severity.Medium)],
            reviewer, limits: new ReviewLimits(4, Generous));

        Assert.Equal(2, result.Detections.Count);
        Assert.All(result.Detections, d => Assert.Equal(Severity.High, d.Severity));
    }

    [Fact]
    public async Task Review_ReviewerIgnoresToken_TimesOutAndKeepsCappedResult()
    {
        using var metrics = new ReviewMetrics();
        var failures = new ConcurrentQueue<string>();
        var reviewer = new FakeReviewer(async (_, _) =>
        {
            await Task.Delay(Timeout.Infinite, CancellationToken.None);
            return new ReviewVerdict(Severity.High, "x");
        });

        var result = await RunAsync(
            [Semantic("TIME-OUT", Vector(Axis.Medium, 0.85f), mapped: true)], reviewer,
            limits: new ReviewLimits(4, TimeSpan.FromMilliseconds(50)), onFailure: failures.Enqueue);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Medium, d.Severity);
        Assert.Equal("Semantic match — capped at Medium pending review", d.Reason);
        Assert.Equal(1, metrics.Count("timed_out", "TIME-OUT"));
        Assert.Single(failures);
    }

    [Fact]
    public async Task Review_ReviewerHonoursToken_TimesOut()
    {
        using var metrics = new ReviewMetrics();
        var reviewer = new FakeReviewer(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return new ReviewVerdict(Severity.High, "x");
        });

        var result = await RunAsync(
            [Semantic("TIME-HONOUR", Vector(Axis.Medium, 0.85f), mapped: true)], reviewer,
            limits: new ReviewLimits(4, TimeSpan.FromMilliseconds(50)));

        Assert.Equal(Severity.Medium, Assert.Single(result.Detections).Severity);
        Assert.Equal(1, metrics.Count("timed_out", "TIME-HONOUR"));
    }

    [Fact]
    public async Task Review_CallerCancels_Propagates()
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var failures = new ConcurrentQueue<string>();
        var logger = new CapturingLogger();
        var reviewer = new FakeReviewer(async (_, token) =>
        {
            await cts.CancelAsync();
            await Task.Delay(Timeout.Infinite, token);
            return new ReviewVerdict(Severity.High, "x");
        });
        var pipeline = new DetectionPipeline(
            [new FakeEscalatingDetector("CANCEL", Severity.Medium)], configurations: null, reviewer: reviewer,
            logger: logger, onDetectorFailure: failures.Enqueue, reviewLimits: new ReviewLimits(4, Generous));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pipeline.RunAsync(Ctx(new ChatMessage(ChatRole.User, ScanText)), cts.Token));

        Assert.Empty(failures);
        Assert.Empty(logger.Warnings);
    }

    [Fact]
    public async Task Review_ReviewerThrowsSynchronously_KeepsCappedResult()
    {
        using var metrics = new ReviewMetrics();
        var reviewer = new FakeReviewer((Func<ReviewRequest, CancellationToken, ValueTask<ReviewVerdict>>)((_, _) =>
            throw new InvalidOperationException("boom")));

        var result = await RunAsync([Semantic("SYNC-THROW", Vector(Axis.Medium, 0.85f), mapped: true)], reviewer);

        var d = Assert.Single(result.Detections);
        Assert.Equal(Severity.Medium, d.Severity);
        Assert.Equal("Semantic match — capped at Medium pending review", d.Reason);
        Assert.Equal(1, metrics.Count("failed", "SYNC-THROW"));
    }

    [Fact]
    public async Task Review_ReasonIsSanitisedAndTruncated()
    {
        const string Prefix = "Reviewed: confirmed — ";
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.Medium, "a\nb\r\n" + new string('x', 10_000)));

        var result = await RunAsync([new FakeEscalatingDetector("REV-SANITISE", Severity.Medium)], reviewer);

        var reason = Assert.Single(result.Detections).Reason;
        Assert.StartsWith(Prefix + "a b x", reason, StringComparison.Ordinal);
        Assert.DoesNotContain('\n', reason);
        Assert.DoesNotContain('\r', reason);
        Assert.InRange(reason.Length - Prefix.Length, 1, 200);
    }

    [Fact]
    public async Task Review_TwoFailures_OneWarningOneFailureCallback()
    {
        var failures = new ConcurrentQueue<string>();
        var logger = new CapturingLogger();
        var reviewer = new FakeReviewer(async (request, _) =>
        {
            await Task.Yield();
            if (request.DetectorId.Value.EndsWith('C')) return new ReviewVerdict(Severity.High, "x");
            throw new InvalidOperationException("boom");
        });
        var pipeline = new DetectionPipeline(
            [
                new FakeEscalatingDetector("FAIL-A", Severity.Medium),
                new FakeEscalatingDetector("FAIL-B", Severity.Medium),
                new FakeEscalatingDetector("FAIL-C", Severity.Medium),
            ],
            configurations: null, reviewer: reviewer, logger: logger, onDetectorFailure: failures.Enqueue);

        var result = await pipeline.RunAsync(Ctx(new ChatMessage(ChatRole.User, ScanText)), TestContext.Current.CancellationToken);

        const string Expected = "AI.Sentinel: 2 of 3 reviews failed or timed out; those detections keep their capped severity.";
        Assert.Equal(Expected, Assert.Single(failures));
        Assert.Equal(Expected, Assert.Single(logger.Warnings));
        Assert.Equal(Severity.Medium, result.Detections.Single(d => string.Equals(d.DetectorId.Value, "FAIL-A", StringComparison.Ordinal)).Severity);
        Assert.Equal(Severity.High, result.Detections.Single(d => string.Equals(d.DetectorId.Value, "FAIL-C", StringComparison.Ordinal)).Severity);
    }

    // ---- configuration ----

    [Fact]
    public async Task Review_SeverityCapLow_AtOrAboveMediumNotACandidate_BandCandidateLimitedToCap()
    {
        var configurations = Config<TestSemanticDetector>(c => c.SeverityCap = Severity.Low);
        var reviewer = new FakeReviewer((_, _) => new ReviewVerdict(Severity.High, "x"));

        // A High bucket hit, capped at Low by configuration: not reviewed.
        var bucket = await RunAsync([Semantic("CAPLOW-BUCKET", Vector(Axis.High, 0.95f))], reviewer, configurations: configurations);
        Assert.Equal(Severity.Low, Assert.Single(bucket.Detections).Severity);
        Assert.Empty(reviewer.Requests);

        // A text below every bucket but above the review threshold: reviewed, and the verdict is held to the cap.
        var band = await RunAsync(
            [Semantic("CAPLOW-BAND", Vector(Axis.Medium, 0.7f), reviewThreshold: 0.6f)], reviewer, configurations: configurations);
        var d = Assert.Single(band.Detections);
        Assert.Equal(Severity.Low, d.Severity);
        Assert.StartsWith("Reviewed: raised", d.Reason, StringComparison.Ordinal);
        Assert.Equal(Severity.Low, Assert.Single(reviewer.Requests).MaximumSeverity);
    }

    [Fact]
    public async Task Review_NoReviewer_KeepsCappedResult()
    {
        var result = await RunAsync([Semantic("NOREV", Vector(Axis.Medium, 0.85f), mapped: true)], reviewer: null);

        Assert.Equal(Severity.Medium, Assert.Single(result.Detections).Severity);
    }

    // ---- helpers ----

    private const string ScanText = "the scanned text";

    private static SentinelContext Ctx(params ChatMessage[] messages) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>());

    private static IReadOnlyDictionary<Type, DetectorConfiguration> Config<T>(Action<DetectorConfiguration> configure)
    {
        var cfg = new DetectorConfiguration();
        configure(cfg);
        return new Dictionary<Type, DetectorConfiguration> { [typeof(T)] = cfg };
    }

    private static async Task<PipelineResult> RunAsync(
        IDetector[] detectors,
        IDetectionReviewer? reviewer,
        SentinelContext? ctx = null,
        IReadOnlyDictionary<Type, DetectorConfiguration>? configurations = null,
        ReviewLimits? limits = null,
        Action<string>? onFailure = null)
    {
        var pipeline = new DetectionPipeline(
            detectors, configurations, reviewer: reviewer, onDetectorFailure: onFailure, reviewLimits: limits);
        return await pipeline.RunAsync(ctx ?? Ctx(new ChatMessage(ChatRole.User, ScanText)), TestContext.Current.CancellationToken);
    }

    /// <summary>A semantic detector that embeds <paramref name="text"/> as <paramref name="vector"/>.</summary>
    private static TestSemanticDetector Semantic(
        string id, float[] vector, bool mapped = false, float? reviewThreshold = null, string text = ScanText) =>
        new(new SentinelOptions
        {
            EmbeddingGenerator = new VectorEmbeddingGenerator(t => string.Equals(t, text, StringComparison.Ordinal) ? vector : Examples(t)),
        }, new DetectorId(id), mapped, reviewThreshold);

    private enum Axis { High = 0, Medium = 1, Low = 2 }

    private const int Dimensions = 8;
    private const int NoiseAxis = 6;
    private const int OrthogonalAxis = 7;

    /// <summary>A unit vector at <paramref name="cosine"/> from the example on <paramref name="axis"/>, orthogonal to the others.</summary>
    private static float[] Vector(Axis axis, float cosine)
    {
        var v = new float[Dimensions];
        v[(int)axis] = cosine;
        v[NoiseAxis] = MathF.Sqrt(1f - (cosine * cosine));
        return v;
    }

    /// <summary>The examples on their own axes; any other text orthogonal to all of them.</summary>
    private static float[] Examples(string text)
    {
        var v = new float[Dimensions];
        var axis = text switch
        {
            HighExample => (int)Axis.High,
            MediumExample => (int)Axis.Medium,
            LowExample => (int)Axis.Low,
            _ => OrthogonalAxis,
        };
        v[axis] = 1f;
        return v;
    }

    /// <summary>Default thresholds: High 0.90, Medium 0.82, Low 0.75. With <c>mapped</c>, its buckets map upward like
    /// SEC-01: Low to Medium, Medium to High, High to Critical.</summary>
    private sealed class TestSemanticDetector(SentinelOptions options, DetectorId id, bool mapped, float? reviewThreshold)
        : SemanticDetectorBase(options)
    {
        protected override string ReviewCriterion => TestCriterion;
        public override DetectorId Id => id;
        public override DetectorCategory Category => DetectorCategory.Security;
        protected override string[] HighExamples => [HighExample];
        protected override string[] MediumExamples => [MediumExample];
        protected override string[] LowExamples => [LowExample];
        protected override Severity HighSeverity => mapped ? Severity.Critical : Severity.High;
        protected override Severity MediumSeverity => mapped ? Severity.High : Severity.Medium;
        protected override Severity LowSeverity => mapped ? Severity.Medium : Severity.Low;
        protected override Severity FastPathSeverity => Severity.Critical;
        protected override Regex? FastPathPattern => new(FastPathText, RegexOptions.None, TimeSpan.FromSeconds(1));
        protected override float ReviewThreshold => reviewThreshold ?? base.ReviewThreshold;
    }

    private sealed class FakeEscalatingDetector(string id, Severity severity) : ILlmEscalatingDetector
    {
        public const string Criterion = "A rule-based test detector; its criterion reaches the reviewer.";
        public string ReviewCriterion => Criterion;
        public DetectorId Id { get; } = new(id);
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(Id)
                : DetectionResult.WithSeverity(Id, severity, "fake"));
    }

    /// <summary>Records each request and answers with a scripted verdict, delay or failure.</summary>
    private sealed class FakeReviewer(Func<ReviewRequest, CancellationToken, ValueTask<ReviewVerdict>> review) : IDetectionReviewer
    {
        public FakeReviewer(Func<ReviewRequest, CancellationToken, ReviewVerdict> verdict)
            : this((r, ct) => ValueTask.FromResult(verdict(r, ct))) { }

        public ConcurrentQueue<ReviewRequest> Requests { get; } = new();

        public ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken)
        {
            Requests.Enqueue(request);
            return review(request, cancellationToken);
        }
    }

    private sealed class VectorEmbeddingGenerator(Func<string, float[]> vectors) : IEmbeddingGenerator<string, Embedding<float>>
    {
        public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new GeneratedEmbeddings<Embedding<float>>(values.Select(v => new Embedding<float>(vectors(v)))));

        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }

    private sealed class CapturingLogger : ILogger<DetectionPipeline>
    {
        public ConcurrentQueue<string> Warnings { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning) Warnings.Enqueue(formatter(state, exception));
        }
    }

    /// <summary>Collects <c>sentinel.reviews</c> measurements. Tests filter by a detector-ID prefix of their own,
    /// because other test classes run in parallel and may record reviews too.</summary>
    private sealed class ReviewMetrics : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentQueue<(string Outcome, string Detector, long Value)> _measurements = new();

        public ReviewMetrics()
        {
            _listener.InstrumentPublished = (instrument, l) =>
            {
                if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal) &&
                    string.Equals(instrument.Name, "sentinel.reviews", StringComparison.Ordinal))
                    l.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                string outcome = "", detector = "";
                foreach (var tag in tags)
                {
                    if (string.Equals(tag.Key, "outcome", StringComparison.Ordinal)) outcome = tag.Value?.ToString() ?? "";
                    else if (string.Equals(tag.Key, "detector", StringComparison.Ordinal)) detector = tag.Value?.ToString() ?? "";
                }
                _measurements.Enqueue((outcome, detector, value));
            });
            _listener.Start();
        }

        /// <summary>The sum recorded with <paramref name="outcome"/>, or any outcome when null, for detectors whose ID
        /// starts with <paramref name="detectorPrefix"/>.</summary>
        public long Count(string? outcome, string detectorPrefix) => _measurements
            .Where(m => (outcome is null || string.Equals(m.Outcome, outcome, StringComparison.Ordinal))
                && m.Detector.StartsWith(detectorPrefix, StringComparison.Ordinal))
            .Sum(m => m.Value);

        public void Dispose() => _listener.Dispose();
    }
}
