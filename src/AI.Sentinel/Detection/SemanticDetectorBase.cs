using Microsoft.Extensions.AI;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>Base class for embedding-based semantic threat detectors.</summary>
/// <remarks>
/// Subclasses declare <see cref="HighExamples"/>, <see cref="MediumExamples"/>, and
/// <see cref="LowExamples"/> representative phrases. At first scan, all examples are
/// embedded via <see cref="Microsoft.Extensions.AI.IEmbeddingGenerator{TInput,TEmbedding}"/>
/// and cached in-process. Each incoming message is embedded and compared by cosine similarity
/// against the reference vectors; the first bucket whose max similarity exceeds its threshold
/// returns the corresponding severity.
/// <para>
/// When <see cref="SentinelOptions.EmbeddingGenerator"/> is <see langword="null"/>,
/// all scans return <see cref="DetectionResult.Clean"/>.
/// </para>
/// </remarks>
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

    /// <summary>Representative phrases that indicate a high-severity threat.</summary>
    protected abstract string[] HighExamples   { get; }
    /// <summary>Representative phrases that indicate a medium-severity threat.</summary>
    protected abstract string[] MediumExamples { get; }
    /// <summary>Representative phrases that indicate a low-severity threat.</summary>
    protected abstract string[] LowExamples    { get; }

    /// <summary>Severity returned when the High bucket threshold is exceeded. Defaults to <see cref="Severity.High"/>.</summary>
    protected virtual Severity HighSeverity   => Severity.High;
    /// <summary>Severity returned when the Medium bucket threshold is exceeded. Defaults to <see cref="Severity.Medium"/>.</summary>
    protected virtual Severity MediumSeverity => Severity.Medium;
    /// <summary>Severity returned when the Low bucket threshold is exceeded. Defaults to <see cref="Severity.Low"/>.</summary>
    protected virtual Severity LowSeverity    => Severity.Low;

    protected virtual float HighThreshold   => 0.90f;
    protected virtual float MediumThreshold => 0.82f;
    protected virtual float LowThreshold    => 0.75f;

    /// <summary>Extracts the text to embed from the context. Override to scan a specific message role.</summary>
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
