using Microsoft.Extensions.AI;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

public abstract class SemanticDetectorBase : IDetector
{
    private readonly IEmbeddingGenerator<string, Embedding<float>>? _generator;
    private readonly IEmbeddingCache _cache;
    private ReadOnlyMemory<float>[]? _highVectors;
    private ReadOnlyMemory<float>[]? _mediumVectors;
    private ReadOnlyMemory<float>[]? _lowVectors;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private volatile bool _initialized;

    protected SemanticDetectorBase(SentinelOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _generator = options.EmbeddingGenerator;
        _cache = options.EmbeddingCache ?? new InMemoryLruEmbeddingCache();
    }

    public abstract DetectorId Id { get; }
    public abstract DetectorCategory Category { get; }

    protected abstract string[] HighExamples   { get; }
    protected abstract string[] MediumExamples { get; }
    protected abstract string[] LowExamples    { get; }

    protected virtual Severity HighSeverity   => Severity.High;
    protected virtual Severity MediumSeverity => Severity.Medium;
    protected virtual Severity LowSeverity    => Severity.Low;

    protected virtual float HighThreshold   => 0.90f;
    protected virtual float MediumThreshold => 0.82f;
    protected virtual float LowThreshold    => 0.75f;

    protected virtual string GetText(SentinelContext ctx) => ctx.TextContent;

    public async ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        if (_generator is null)
            return DetectionResult.Clean(Id);

        await EnsureInitializedAsync(ct).ConfigureAwait(false);

        var text = GetText(ctx);
        if (string.IsNullOrWhiteSpace(text))
            return DetectionResult.Clean(Id);

        var vector = await GetEmbeddingAsync(text, ct).ConfigureAwait(false);

        if (_highVectors is { Length: > 0 } && MaxSimilarity(vector.Span, _highVectors) >= HighThreshold)
            return DetectionResult.WithSeverity(Id, HighSeverity, "Semantic match — high-severity threat pattern");
        if (_mediumVectors is { Length: > 0 } && MaxSimilarity(vector.Span, _mediumVectors) >= MediumThreshold)
            return DetectionResult.WithSeverity(Id, MediumSeverity, "Semantic match — medium-severity threat pattern");
        if (_lowVectors is { Length: > 0 } && MaxSimilarity(vector.Span, _lowVectors) >= LowThreshold)
            return DetectionResult.WithSeverity(Id, LowSeverity, "Semantic match — low-severity threat pattern");

        return DetectionResult.Clean(Id);
    }

    private async Task EnsureInitializedAsync(CancellationToken ct)
    {
        if (_initialized) return;
        await _initLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_initialized) return;
            _highVectors   = await EmbedExamplesAsync(HighExamples, ct).ConfigureAwait(false);
            _mediumVectors = await EmbedExamplesAsync(MediumExamples, ct).ConfigureAwait(false);
            _lowVectors    = await EmbedExamplesAsync(LowExamples, ct).ConfigureAwait(false);
            _initialized = true;
        }
        finally { _initLock.Release(); }
    }

    private async Task<ReadOnlyMemory<float>[]> EmbedExamplesAsync(string[] examples, CancellationToken ct)
    {
        if (examples.Length == 0) return [];
        var results = await _generator!.GenerateAsync(examples, cancellationToken: ct).ConfigureAwait(false);
        return [.. results.Select(e => e.Vector)];
    }

    private async Task<ReadOnlyMemory<float>> GetEmbeddingAsync(string text, CancellationToken ct)
    {
        if (_cache.TryGet(text, out var cached))
            return cached.Vector;

        var results = await _generator!.GenerateAsync([text], cancellationToken: ct).ConfigureAwait(false);
        var embedding = results[0];
        _cache.Set(text, embedding);
        return embedding.Vector;
    }

    private static float MaxSimilarity(ReadOnlySpan<float> query, ReadOnlyMemory<float>[] references)
    {
        var max = 0f;
        foreach (var r in references)
        {
            var sim = CosineSimilarity(query, r.Span);
            if (sim > max) max = sim;
        }
        return max;
    }

    private static float CosineSimilarity(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        if (a.Length != b.Length) return 0f;
        float dot = 0f, na = 0f, nb = 0f;
        for (var i = 0; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            na  += a[i] * a[i];
            nb  += b[i] * b[i];
        }
        var denom = MathF.Sqrt(na) * MathF.Sqrt(nb);
        return denom > 0f ? dot / denom : 0f;
    }
}
