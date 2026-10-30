using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>A pipeline with an embedding scope embeds each distinct scan text once, however many semantic detectors
/// score it, and reports a failed input or a failed set of example phrases once per scan instead of once per
/// detector.</summary>
public class EmbedOncePerScanTests
{
    private const string FirstText = "the weather in the harbour was calm this morning";
    private const string SecondText = "please book a table for four at the corner bistro";

    private sealed class TestSemantic(
        string id,
        string[] high,
        Func<SentinelContext, IEnumerable<string>>? texts = null,
        Regex? fastPath = null,
        SentinelOptions? options = null) : SemanticDetectorBase(options ?? new SentinelOptions())
    {
        protected override string ReviewCriterion => "A test-only detector with a generic criterion, never reviewed by a real judge.";
        public override DetectorId Id => new(id);
        public override DetectorCategory Category => DetectorCategory.Security;
        protected override string[] HighExamples => high;
        protected override string[] MediumExamples => [];
        protected override string[] LowExamples => [];
        protected override Regex? FastPathPattern => fastPath;

        protected override IEnumerable<string> GetTextsToScore(SentinelContext ctx) =>
            texts?.Invoke(ctx) ?? base.GetTextsToScore(ctx);
    }

    private sealed class LegacyBlankDetector(string[] high) : SemanticDetectorBase(new SentinelOptions())
    {
        protected override string ReviewCriterion => "A test-only detector with a generic criterion, never reviewed by a real judge.";
        public override DetectorId Id => new("TST-LEGACY");
        public override DetectorCategory Category => DetectorCategory.Security;
        protected override string[] HighExamples => high;
        protected override string[] MediumExamples => [];
        protected override string[] LowExamples => [];

#pragma warning disable CS0672, SENTINEL001
        protected override string GetText(SentinelContext ctx) => "";
#pragma warning restore CS0672, SENTINEL001
    }

    /// <summary>Six detectors with distinct example phrases, none of which matches a scan text.</summary>
    private static List<IDetector> SixDetectors() =>
        [.. Enumerable.Range(1, 6).Select(i => (IDetector)new TestSemantic($"TST-{i}", [$"distinct example phrase number {i}"]))];

    private static SentinelContext Ctx(params ChatMessage[] messages) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>());

    private static ChatMessage User(string text) => new(ChatRole.User, text);
    private static ChatMessage Assistant(string text) => new(ChatRole.Assistant, text);

    private static (DetectionPipeline Pipeline, ConcurrentQueue<string> Failures) Pipeline(
        IEnumerable<IDetector> detectors, YieldingEmbeddingGenerator gen, IEmbeddingCache? scanCache = null)
    {
        var failures = new ConcurrentQueue<string>();
        var pipeline = new DetectionPipeline(
            detectors, configurations: null, escalationClient: null,
            onDetectorFailure: failures.Enqueue,
            embeddingScope: new EmbeddingScope(gen, scanCache ?? new InMemoryLruEmbeddingCache(), null));
        return (pipeline, failures);
    }

    /// <summary>The generator calls whose inputs are all scan texts, so not example-phrase calls.</summary>
    private static List<IReadOnlyList<string>> ScanBatches(YieldingEmbeddingGenerator gen, params string[] scanTexts) =>
        [.. gen.Batches.Where(b => b.All(i => scanTexts.Contains(i, StringComparer.Ordinal)))];

    private static bool Has(PipelineResult result, string id, Severity severity) =>
        result.Detections.Any(d => string.Equals(d.DetectorId.Value, id, StringComparison.Ordinal) && d.Severity == severity);

    private static bool Fired(PipelineResult result, string id) =>
        result.Detections.Any(d => string.Equals(d.DetectorId.Value, id, StringComparison.Ordinal));

    [Fact]
    public async Task Scan_embeds_each_text_once_across_all_detectors()
    {
        var gen = new YieldingEmbeddingGenerator();
        var (pipeline, failures) = Pipeline(SixDetectors(), gen);

        await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), TestContext.Current.CancellationToken);

        var batch = Assert.Single(ScanBatches(gen, FirstText, SecondText));
        Assert.Equal(2, batch.Count);
        Assert.Contains(FirstText, batch, StringComparer.Ordinal);
        Assert.Contains(SecondText, batch, StringComparer.Ordinal);
        Assert.Empty(failures);
    }

    [Fact]
    public async Task Overlapping_texts_across_detectors_embed_once_and_score_own_texts()
    {
        var gen = new YieldingEmbeddingGenerator();
        var userOnly = new TestSemantic("TST-U", [SecondText],
            texts: ctx => ctx.Messages.Where(m => m.Role == ChatRole.User).Select(m => m.Text));
        var all = new TestSemantic("TST-A", [SecondText]);
        var (pipeline, _) = Pipeline([userOnly, all], gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText), Assistant(SecondText)), TestContext.Current.CancellationToken);

        // The user text is no example phrase, so the one call holding it is the scan call.
        var batch = Assert.Single(gen.Batches, b => b.Contains(FirstText, StringComparer.Ordinal));
        Assert.Equal(2, batch.Count);
        Assert.Contains(SecondText, batch, StringComparer.Ordinal);
        Assert.True(Has(result, "TST-A", Severity.High));
        Assert.False(Fired(result, "TST-U"));
    }

    [Fact]
    public async Task Warm_scan_cache_makes_no_scan_call()
    {
        var ct = TestContext.Current.CancellationToken;
        var gen = new YieldingEmbeddingGenerator();
        var cache = new InMemoryLruEmbeddingCache();
        var warm = await new FakeEmbeddingGenerator().GenerateAsync([FirstText, SecondText], cancellationToken: ct);
        cache.Set(FirstText, warm[0]);
        cache.Set(SecondText, warm[1]);
        var (pipeline, failures) = Pipeline(SixDetectors(), gen, cache);

        await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), ct);

        Assert.DoesNotContain(gen.Inputs, i => i is FirstText or SecondText);
        Assert.Empty(failures);
    }

    [Fact]
    public async Task Bad_input_only_skips_itself()
    {
        const string Marked = "MARKED input the provider rejects outright";
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains(Marked, StringComparer.Ordinal));
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-GOOD", [FirstText]));
        var (pipeline, failures) = Pipeline(detectors, gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText), User(Marked)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-GOOD", Severity.High));
        var message = Assert.Single(failures);
        Assert.Contains("1 of 2", message, StringComparison.Ordinal);
        Assert.DoesNotContain(Marked, message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Example_failure_is_reported_once_per_scan()
    {
        const string BrokenExample = "example phrase the provider refuses to embed";
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains(BrokenExample, StringComparer.Ordinal));
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-BROKEN", [BrokenExample, FirstText]));
        detectors.Add(new TestSemantic("TST-GOOD", [FirstText]));
        var (pipeline, failures) = Pipeline(detectors, gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), TestContext.Current.CancellationToken);

        Assert.False(Fired(result, "TST-BROKEN"));
        Assert.True(Has(result, "TST-GOOD", Severity.High));
        var message = Assert.Single(failures);
        Assert.Contains("TST-BROKEN", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Example_failures_of_several_detectors_are_reported_together()
    {
        var gen = new YieldingEmbeddingGenerator(batch => batch.Any(i => i.StartsWith("broken", StringComparison.Ordinal)));
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-B1", ["broken example one"]));
        detectors.Add(new TestSemantic("TST-B2", ["broken example two"]));
        var (pipeline, failures) = Pipeline(detectors, gen);

        await pipeline.RunAsync(Ctx(User(FirstText)), TestContext.Current.CancellationToken);

        var message = Assert.Single(failures);
        Assert.Contains("TST-B1, TST-B2", message, StringComparison.Ordinal);
        Assert.Contains("HttpRequestException", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Example_failure_keeps_the_rule_layer_match()
    {
        // As before the scope: the rule layer needs no vectors, so an embedding outage must not silence it.
        const string BrokenExample = "example phrase the provider refuses to embed";
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains(BrokenExample, StringComparer.Ordinal));
        var detector = new TestSemantic("TST-RULE", [BrokenExample], fastPath: new Regex("calm", RegexOptions.None, TimeSpan.FromSeconds(1)));
        var (pipeline, failures) = Pipeline([detector], gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-RULE", Severity.High));
        Assert.Single(failures);
    }

    [Fact]
    public async Task Provider_timeout_on_scan_texts_keeps_the_rule_layer_and_is_reported_once()
    {
        // HttpClient reports its timeout as a TaskCanceledException while the caller's token is not cancelled.
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains(FirstText, StringComparer.Ordinal))
        {
            Failure = _ => new TaskCanceledException("timed out"),
        };
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-RULE", ["rule detector example phrase"], fastPath: new Regex("calm", RegexOptions.None, TimeSpan.FromSeconds(1))));
        var (pipeline, failures) = Pipeline(detectors, gen);

        // The rule layer reads the newest message, so the matching text comes last.
        var result = await pipeline.RunAsync(Ctx(User(SecondText), User(FirstText)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-RULE", Severity.High));
        Assert.Single(ScanBatches(gen, FirstText, SecondText));
        var message = Assert.Single(failures);
        Assert.Contains("2 of 2", message, StringComparison.Ordinal);
        Assert.Contains("TaskCanceledException", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Provider_timeout_on_example_phrases_is_reported_once_as_an_example_failure()
    {
        const string BrokenExample = "example phrase the provider times out on";
        var gen = new YieldingEmbeddingGenerator(batch => batch.Contains(BrokenExample, StringComparer.Ordinal))
        {
            Failure = _ => new TaskCanceledException("timed out"),
        };
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-BROKEN", [BrokenExample, FirstText]));
        detectors.Add(new TestSemantic("TST-GOOD", [FirstText]));
        var (pipeline, failures) = Pipeline(detectors, gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), TestContext.Current.CancellationToken);

        Assert.False(Fired(result, "TST-BROKEN"));
        Assert.True(Has(result, "TST-GOOD", Severity.High));
        var message = Assert.Single(failures);
        Assert.Contains("example phrases of detector(s) TST-BROKEN", message, StringComparison.Ordinal);
        Assert.Contains("TaskCanceledException", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Provider_timeout_without_scope_is_that_detectors_failure()
    {
        var gen = new YieldingEmbeddingGenerator(_ => true) { Failure = _ => new TaskCanceledException("timed out") };
        var timingOut = new TestSemantic("TST-OPT", [FirstText], options: new SentinelOptions { EmbeddingGenerator = gen });
        var rule = new TestSemantic("TST-RULE", ["rule detector example phrase"], fastPath: new Regex("calm", RegexOptions.None, TimeSpan.FromSeconds(1)));
        var failures = new ConcurrentQueue<string>();
        var pipeline = new DetectionPipeline([timingOut, rule], configurations: null, escalationClient: null, onDetectorFailure: failures.Enqueue);

        var result = await pipeline.RunAsync(Ctx(User(FirstText)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-RULE", Severity.High));
        var message = Assert.Single(failures);
        Assert.Contains("TST-OPT", message, StringComparison.Ordinal);
        Assert.Contains("TaskCanceledException", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Detector_scores_exactly_the_texts_collected_for_the_scan()
    {
        // An override that answers differently on each call: the first call is the one the pipeline embeds, and
        // scoring a second, different list would look up texts that are not in the scan and skip them unreported.
        var calls = 0;
        var gen = new YieldingEmbeddingGenerator();
        var stateful = new TestSemantic("TST-STATEFUL", [FirstText],
            texts: _ => Interlocked.Increment(ref calls) == 1 ? [FirstText] : [SecondText]);
        var (pipeline, failures) = Pipeline([stateful], gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), TestContext.Current.CancellationToken);

        Assert.Equal(1, calls);
        Assert.True(Has(result, "TST-STATEFUL", Severity.High));
        Assert.DoesNotContain(gen.Inputs, i => i is SecondText);
        Assert.Empty(failures);
    }

    [Fact]
    public async Task Throwing_text_selection_is_reported_as_that_detectors_failure()
    {
        var gen = new YieldingEmbeddingGenerator();
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-THROWS", [FirstText], texts: _ => throw new InvalidOperationException("selection failed")));
        detectors.Add(new TestSemantic("TST-GOOD", [FirstText]));
        var (pipeline, failures) = Pipeline(detectors, gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-GOOD", Severity.High));
        Assert.False(Fired(result, "TST-THROWS"));
        var message = Assert.Single(failures);
        Assert.Contains("detector TST-THROWS failed", message, StringComparison.Ordinal);
    }

    private sealed class ThrowingCache : IEmbeddingCache
    {
        public bool TryGet(string text, out Embedding<float> embedding) =>
            throw new InvalidOperationException("cache unavailable");
        public void Set(string text, Embedding<float> embedding) =>
            throw new InvalidOperationException("cache unavailable");
    }

    [Fact]
    public async Task Throwing_scan_cache_fails_every_text_once_and_rule_layer_still_runs()
    {
        var gen = new YieldingEmbeddingGenerator();
        var detectors = SixDetectors();
        detectors.Add(new TestSemantic("TST-RULE", [FirstText], fastPath: new Regex("calm", RegexOptions.None, TimeSpan.FromSeconds(1))));
        var (pipeline, failures) = Pipeline(detectors, gen, new ThrowingCache());

        // The rule layer reads the newest message, so the matching text comes last.
        var result = await pipeline.RunAsync(Ctx(User(SecondText), User(FirstText)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-RULE", Severity.High));
        var message = Assert.Single(failures);
        Assert.Contains("2 of 2", message, StringComparison.Ordinal);
        Assert.Contains("InvalidOperationException", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Legacy_blank_GetText_contributes_no_texts()
    {
        var gen = new YieldingEmbeddingGenerator();
        var detectors = SixDetectors();
        detectors.Add(new LegacyBlankDetector([FirstText]));
        var (pipeline, failures) = Pipeline(detectors, gen);

        var result = await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), TestContext.Current.CancellationToken);

        Assert.False(Fired(result, "TST-LEGACY"));
        var batch = Assert.Single(ScanBatches(gen, FirstText, SecondText));
        Assert.Equal(2, batch.Count);
        Assert.DoesNotContain(gen.Inputs, i => i is "");
        Assert.Empty(failures);
    }

    [Fact]
    public async Task Pipeline_without_scope_uses_detector_options()
    {
        var gen = new YieldingEmbeddingGenerator();
        var detector = new TestSemantic("TST-OPT", [FirstText], options: new SentinelOptions { EmbeddingGenerator = gen });
        var pipeline = new DetectionPipeline([detector], configurations: null, escalationClient: null);

        var result = await pipeline.RunAsync(Ctx(User(FirstText)), TestContext.Current.CancellationToken);

        Assert.True(Has(result, "TST-OPT", Severity.High));
    }

    [Fact]
    public async Task Cancellation_propagates_from_precompute()
    {
        var gen = new YieldingEmbeddingGenerator();
        var (pipeline, failures) = Pipeline(SixDetectors(), gen);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pipeline.RunAsync(Ctx(User(FirstText), User(SecondText)), cts.Token));

        Assert.Empty(failures);
    }
}
