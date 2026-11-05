using System.Globalization;
using System.Text.Json;
using AI.Sentinel.Approvals.Semantic;
using AI.Sentinel.Detection;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Semantic;

public class SemanticApprovalMatcherTests
{
    private const int Max = 1024;

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static JsonElement Command(string command) =>
        Json($$"""{"command":"{{JsonEncodedText.Encode(command)}}"}""");

    private static SemanticApprovalMatcher Matcher(
        IEmbeddingGenerator<string, Embedding<float>> generator,
        SemanticApprovalSettings? settings = null,
        SemanticApprovalSpec? spec = null,
        int maxBytes = Max) =>
        new(new EmbeddingScope(generator, new InMemoryLruEmbeddingCache(), null),
            settings ?? new SemanticApprovalSettings(),
            [("Bash", spec ?? new SemanticApprovalSpec { BackendBinding = "Operator" })],
            maxBytes);

    [Fact]
    public async Task VerbatimExample_Flagged_WithScoreAndExample()
    {
        var spec = new SemanticApprovalSpec { BackendBinding = "Operator" };
        var matcher = Matcher(new ExactMatchEmbeddingGenerator(), spec: spec);

        var match = await matcher.MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        var flagged = Assert.IsType<SemanticMatch.Flagged>(match);
        Assert.Equal("Bash", flagged.Key);
        Assert.Same(spec, flagged.Spec);
        Assert.Equal(1f, flagged.Score, 5);
        Assert.Equal(SemanticApprovalExamples.DefaultThreshold, flagged.Threshold);
        Assert.Equal("$.command", flagged.Path);
        Assert.Equal("rm -rf /", flagged.Example);
        Assert.False(flagged.Truncated);
    }

    [Fact]
    public async Task UnrelatedText_NotFlagged()
    {
        var match = await Matcher(new ExactMatchEmbeddingGenerator()).MatchAsync("Bash", Command("ls -la"), CancellationToken.None);

        var notFlagged = Assert.IsType<SemanticMatch.NotFlagged>(match);
        Assert.Null(notFlagged.Reason);
    }

    [Fact]
    public async Task NoTexts_NotFlagged_WithoutGeneratorRequest()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());

        var match = await Matcher(recording).MatchAsync("Bash", Json("""{"description":"x"}"""), CancellationToken.None);

        Assert.IsType<SemanticMatch.NotFlagged>(match);
        Assert.Equal(0, recording.Calls);
    }

    [Fact]
    public async Task ScoreEqualToThreshold_Flagged()
    {
        var spec = new SemanticApprovalSpec { BackendBinding = "Operator", Threshold = 1f };

        var match = await Matcher(new ExactMatchEmbeddingGenerator(), spec: spec).MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        var flagged = Assert.IsType<SemanticMatch.Flagged>(match);
        Assert.Equal(1f, flagged.Threshold);
        Assert.Equal(1f, flagged.Score);
    }

    [Fact]
    public async Task ScoreBelowThreshold_NotFlagged()
    {
        // Cosine 0.5 between the call and the only example.
        var generator = new VectorEmbeddingGenerator(t => string.Equals(t, "decommission a tenant", StringComparison.Ordinal) ? [1f, 0f] : [0.5f, MathF.Sqrt(0.75f)]);
        var settings = new SemanticApprovalSettings { ReplaceExamples = true, Threshold = 0.6f }.AddExamples("decommission a tenant");

        var match = await Matcher(generator, settings).MatchAsync("Bash", Command("something else"), CancellationToken.None);

        Assert.IsType<SemanticMatch.NotFlagged>(match);
    }

    [Fact]
    public async Task Threshold_SpecOverridesSettings_SettingsOverrideDefault()
    {
        var settings = new SemanticApprovalSettings { Threshold = 0.9f };

        var fromSettings = await Matcher(new ExactMatchEmbeddingGenerator(), settings).MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);
        var fromSpec = await Matcher(new ExactMatchEmbeddingGenerator(), settings, new SemanticApprovalSpec { Threshold = 0.95f })
            .MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        Assert.Equal(0.9f, Assert.IsType<SemanticMatch.Flagged>(fromSettings).Threshold);
        Assert.Equal(0.95f, Assert.IsType<SemanticMatch.Flagged>(fromSpec).Threshold);
    }

    [Fact]
    public async Task ReplaceExamples_IgnoresDefaults()
    {
        var settings = new SemanticApprovalSettings { ReplaceExamples = true }.AddExamples("decommission a tenant");
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());

        var match = await Matcher(recording, settings).MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        Assert.IsType<SemanticMatch.NotFlagged>(match);
        Assert.DoesNotContain("kubectl delete namespace production", recording.Inputs, StringComparer.Ordinal);
    }

    [Fact]
    public async Task AddedExample_Matches()
    {
        var settings = new SemanticApprovalSettings().AddExamples("decommission a tenant");
        var matcher = Matcher(new ExactMatchEmbeddingGenerator(), settings);

        var added = await matcher.MatchAsync("Bash", Command("decommission a tenant"), CancellationToken.None);
        var builtIn = await matcher.MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        Assert.Equal("decommission a tenant", Assert.IsType<SemanticMatch.Flagged>(added).Example);
        Assert.Equal("rm -rf /", Assert.IsType<SemanticMatch.Flagged>(builtIn).Example);
    }

    [Fact]
    public async Task SettingsChangedAfterConstruction_DoNotAffectMatcher()
    {
        var settings = new SemanticApprovalSettings();
        var matcher = Matcher(new ExactMatchEmbeddingGenerator(), settings);
        settings.ReplaceExamples = true;
        settings.AddExamples("decommission a tenant");

        var match = await matcher.MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        Assert.IsType<SemanticMatch.Flagged>(match);
    }

    [Fact]
    public void ReplaceExamples_WithoutExamples_Throws()
    {
        var settings = new SemanticApprovalSettings { ReplaceExamples = true };

        Assert.Throws<ArgumentException>(() => Matcher(new ExactMatchEmbeddingGenerator(), settings));
    }

    [Fact]
    public async Task GeneratorThrows_Failed_WithKind()
    {
        var generator = new VectorEmbeddingGenerator(_ => throw new HttpRequestException("down"));

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        var failed = Assert.IsType<SemanticMatch.Failed>(match);
        Assert.Equal("HttpRequestException", failed.Kind);
        Assert.False(failed.Truncated);
    }

    [Fact]
    public async Task GeneratorTimesOut_WhileCallerLive_Failed()
    {
        var generator = new VectorEmbeddingGenerator(_ => throw new TaskCanceledException("timeout"));

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        Assert.Equal("TaskCanceledException", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task CallTextEmbeddingFails_Failed_WithKind()
    {
        // Examples embed fine; only the call's text is rejected.
        var generator = new VectorEmbeddingGenerator(t => string.Equals(t, "drop it all", StringComparison.Ordinal) ? throw new HttpRequestException("rejected") : [1f, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("drop it all"), CancellationToken.None);

        Assert.Equal("HttpRequestException", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task WrongCount_Failed()
    {
        var generator = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator(), dropLast: true);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /"), CancellationToken.None);

        Assert.Equal("InvalidOperationException", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task DimensionMismatch_Failed()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f, 0f, 0f] : [1f, 0f, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal("dimension mismatch", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task ExampleDimensionsDiffer_Failed()
    {
        var generator = new VectorEmbeddingGenerator(t => string.Equals(t, "rm -rf /", StringComparison.Ordinal) ? [1f, 0f, 0f, 0f] : [1f, 0f, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal("dimension mismatch", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task Wrong_length_call_vector_is_not_cached_so_the_next_call_is_scored()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f, 0f] : [1f, 0f]);
        var matcher = Matcher(generator);

        var first = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);
        generator.Vectors = _ => [1f, 0f, 0f];
        var second = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(InvalidEmbeddingException.DimensionMismatch, Assert.IsType<SemanticMatch.Failed>(first).Kind);
        Assert.IsType<SemanticMatch.Flagged>(second);
    }

    [Fact]
    public async Task EmptyVector_Failed()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f] : []);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal("empty vector", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task EmptyExampleVector_Failed_AndRetriedOnNextCall()
    {
        var empty = true;
        var generator = new VectorEmbeddingGenerator(_ => empty ? [] : [1f, 0f]);
        var matcher = Matcher(generator);

        var first = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);
        empty = false;
        var second = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/y"), CancellationToken.None);

        Assert.Equal("empty vector", Assert.IsType<SemanticMatch.Failed>(first).Kind);
        Assert.IsType<SemanticMatch.Flagged>(second);
    }

    [Fact]
    public async Task Failed_Truncated_WhenTextWasCut()
    {
        var generator = new VectorEmbeddingGenerator(_ => throw new HttpRequestException("down"));

        var match = await Matcher(generator, maxBytes: 4).MatchAsync("Bash", Command("rm -rf /var/lib"), CancellationToken.None);

        var failed = Assert.IsType<SemanticMatch.Failed>(match);
        Assert.True(failed.Truncated);
        Assert.EndsWith(" (text truncated)", failed.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Flagged_Truncated_WhenAnyTextWasCut()
    {
        var spec = new SemanticApprovalSpec().Paths("$.command", "$.extra");
        var args = Json("""{"command":"rm -rf /","extra":"a long text that does not fit"}""");

        var match = await Matcher(new ExactMatchEmbeddingGenerator(), spec: spec, maxBytes: 10).MatchAsync("Bash", args, CancellationToken.None);

        var flagged = Assert.IsType<SemanticMatch.Flagged>(match);
        Assert.Equal("$.command", flagged.Path);
        Assert.True(flagged.Truncated);
    }

    [Fact]
    public async Task CallerCancelled_Throws()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Matcher(new ExactMatchEmbeddingGenerator()).MatchAsync("Bash", Command("rm -rf /"), cts.Token).AsTask());
    }

    [Fact]
    public async Task CallerCancelledDuringRequest_ProviderException_Throws()
    {
        using var cts = new CancellationTokenSource();
        var generator = new VectorEmbeddingGenerator(_ =>
        {
            cts.Cancel();
            throw new HttpRequestException("aborted");
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Matcher(generator).MatchAsync("Bash", Command("rm -rf /"), cts.Token).AsTask());
    }

    [Fact]
    public async Task CallTextCached_SecondCallNoGeneratorRequest()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var matcher = Matcher(recording);

        await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);
        var calls = recording.Calls;
        var match = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(calls, recording.Calls);
        Assert.IsType<SemanticMatch.NotFlagged>(match);
    }

    [Fact]
    public async Task Examples_EmbeddedOncePerGenerator()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var matcher = Matcher(recording);

        await matcher.MatchAsync("Bash", Command("one"), CancellationToken.None);
        await matcher.MatchAsync("Bash", Command("two"), CancellationToken.None);

        Assert.Equal(1, recording.Inputs.Count(i => string.Equals(i, "rm -rf /", StringComparison.Ordinal)));
    }

    [Fact]
    public void Covers_FirstMatchingPatternWins_Ordinal()
    {
        var first = new SemanticApprovalSpec { BackendBinding = "A" };
        var second = new SemanticApprovalSpec { BackendBinding = "B" };
        var matcher = new SemanticApprovalMatcher(
            new EmbeddingScope(new ExactMatchEmbeddingGenerator(), new InMemoryLruEmbeddingCache(), null),
            new SemanticApprovalSettings(),
            [("mcp__k8s__*", first), ("mcp__k8s__delete", second), ("Bash", second)],
            Max);

        Assert.True(matcher.Covers("mcp__k8s__delete", out var key, out var spec));
        Assert.Equal("mcp__k8s__*", key);
        Assert.Same(first, spec);
        Assert.True(matcher.Covers("Bash", out key, out _));
        Assert.Equal("Bash", key);
        Assert.False(matcher.Covers("bash", out _, out _));
        Assert.False(matcher.Covers("Read", out _, out _));
    }

    [Fact]
    public async Task ZeroCallVector_Failed_InvalidVector()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f] : [0f, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal("invalid vector", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task Invalid_call_vector_fails_with_its_kind()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f, 0f] : [0f, 0f, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(InvalidEmbeddingException.InvalidVector, Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task Invalid_call_vector_is_not_cached_so_the_next_call_is_scored()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f, 0f] : [0f, 0f, 0f]);
        var matcher = Matcher(generator);

        var first = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);
        generator.Vectors = _ => [1f, 0f, 0f];
        var second = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(InvalidEmbeddingException.InvalidVector, Assert.IsType<SemanticMatch.Failed>(first).Kind);
        Assert.IsType<SemanticMatch.Flagged>(second);
    }

    [Fact]
    public async Task Wrong_length_call_vector_fails_with_dimension_mismatch()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f, 0f] : [1f, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(InvalidEmbeddingException.DimensionMismatch, Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Fact]
    public async Task NaNCallVector_Failed_InvalidVector()
    {
        var examples = new HashSet<string>(SemanticApprovalExamples.Default, StringComparer.Ordinal);
        var generator = new VectorEmbeddingGenerator(t => examples.Contains(t) ? [1f, 0f] : [float.NaN, 1f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal("invalid vector", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Theory]
    [InlineData(1e20f)]
    [InlineData(1e-25f)]
    public async Task ExtremeFiniteVectors_ScoredNotDropped(float scale)
    {
        var generator = new VectorEmbeddingGenerator(_ => [scale, 0f]);

        var match = await Matcher(generator).MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(1f, Assert.IsType<SemanticMatch.Flagged>(match).Score, 5);
    }

    [Theory]
    [InlineData("empty", "empty vector")]
    [InlineData("zero", "invalid vector")]
    [InlineData("infinite", "invalid vector")]
    [InlineData("uneven", "dimension mismatch")]
    public async Task PersistentExampleCache_BadResponseNotCached_NextCallFlagged(string bad, string kind)
    {
        var valid = false;
        var generator = new VectorEmbeddingGenerator(t => valid ? [1f, 0f] : bad switch
        {
            "empty" => [],
            "zero" => [0f, 0f],
            "infinite" => [float.PositiveInfinity, 0f],
            _ => string.Equals(t, "rm -rf /", StringComparison.Ordinal) ? [1f, 0f, 0f] : [1f, 0f],
        });
        var exampleCache = new InMemoryLruEmbeddingCache();
        var matcher = new SemanticApprovalMatcher(
            new EmbeddingScope(generator, new InMemoryLruEmbeddingCache(), exampleCache),
            new SemanticApprovalSettings(), [("Bash", new SemanticApprovalSpec())], Max);

        var first = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);
        Assert.False(exampleCache.TryGet("rm -rf /", out _));
        valid = true;
        var second = await matcher.MatchAsync("Bash", Command("rm -rf /tmp/x"), CancellationToken.None);

        Assert.Equal(kind, Assert.IsType<SemanticMatch.Failed>(first).Kind);
        Assert.IsType<SemanticMatch.Flagged>(second);
        Assert.True(exampleCache.TryGet("rm -rf /", out var cached));
        Assert.Equal(2, cached.Vector.Length);
    }

    [Fact]
    public async Task UnreadableArguments_Failed_WithKind()
    {
        var doc = JsonDocument.Parse("""{"command":"rm -rf /"}""");
        var args = doc.RootElement;
        doc.Dispose();

        var match = await Matcher(new ExactMatchEmbeddingGenerator()).MatchAsync("Bash", args, CancellationToken.None);

        Assert.Equal("ObjectDisposedException", Assert.IsType<SemanticMatch.Failed>(match).Kind);
    }

    [Theory]
    [InlineData("Bash", """{"command":"ls","command":"rm -rf /"}""", "duplicate key")]
    [InlineData("db_query", """{"sql":"DROP TABLE a","note":"\ud800"}""", "unreadable arguments")]
    public async Task UndecidableArgumentText_Failed_WithoutGeneratorRequest(string tool, string json, string kind)
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var matcher = new SemanticApprovalMatcher(
            new EmbeddingScope(recording, new InMemoryLruEmbeddingCache(), null),
            new SemanticApprovalSettings(), [(tool, new SemanticApprovalSpec { BackendBinding = "Operator" })], Max);

        var match = await matcher.MatchAsync(tool, Json(json), CancellationToken.None);

        var failed = Assert.IsType<SemanticMatch.Failed>(match);
        Assert.Equal(kind, failed.Kind);
        Assert.Equal($"Semantic check failed: {kind}; approval required (fail closed)", failed.Reason);
        Assert.Equal(0, recording.Calls);
    }

    [Fact]
    public void Reason_Copy_MatchesSpec()
    {
        var spec = new SemanticApprovalSpec();

        Assert.Null(new SemanticMatch.NotFlagged("Bash", spec).Reason);
        Assert.Equal(
            "Semantic match 0.87 ≥ 0.80 on $.command: \"delete a Kubernetes namespace\"",
            new SemanticMatch.Flagged("Bash", spec, 0.8712f, 0.8f, "$.command", "delete a Kubernetes namespace", false).Reason);
        Assert.Equal(
            "Semantic match 0.87 ≥ 0.80 on $: \"delete a Kubernetes namespace\" (text truncated)",
            new SemanticMatch.Flagged("Bash", spec, 0.8712f, 0.8f, "$", "delete a Kubernetes namespace", true).Reason);
        Assert.Equal(
            "Semantic check failed: HttpRequestException; approval required (fail closed)",
            new SemanticMatch.Failed("Bash", spec, "HttpRequestException", false).Reason);
        Assert.Equal(
            "Semantic check failed: dimension mismatch; approval required (fail closed) (text truncated)",
            new SemanticMatch.Failed("Bash", spec, "dimension mismatch", true).Reason);
    }

    [Fact]
    public void Reason_Copy_IgnoresCurrentCulture()
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("nl-NL");

            Assert.Equal(
                "Semantic match 0.87 ≥ 0.80 on $.command: \"x\"",
                new SemanticMatch.Flagged("Bash", new SemanticApprovalSpec(), 0.8712f, 0.8f, "$.command", "x", false).Reason);
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }
}

/// <summary>Resolves the key and spec through <see cref="SemanticApprovalMatcher.Covers"/>, as the guard does.</summary>
file static class MatcherTestExtensions
{
    public static ValueTask<SemanticMatch> MatchAsync(this SemanticApprovalMatcher matcher, string toolName, JsonElement args, CancellationToken ct)
    {
        Assert.True(matcher.Covers(toolName, out var key, out var spec));
        return matcher.MatchAsync(toolName, args, key, spec, ct);
    }
}
