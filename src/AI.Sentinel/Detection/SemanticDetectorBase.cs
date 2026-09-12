using System.Text.RegularExpressions;
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
    private readonly IEmbeddingCache? _exampleCache;
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
        _exampleCache = options.ExampleEmbeddingCache;
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

    /// <summary>High-precision pattern checked before any embedding call. A match returns
    /// <see cref="FastPathSeverity"/> immediately.</summary>
    /// <remarks>
    /// This is what lets a detector degrade instead of disappearing: semantic detection is off in a
    /// default install, so without a rule layer SEC-01 and SEC-05 return Clean for a textbook
    /// injection. It also short-circuits the obvious cases when a generator <em>is</em> configured,
    /// saving a round-trip.
    /// <para>
    /// Only unambiguous phrasings belong here. The regex detectors these replaced carried loose
    /// patterns — <c>pretend you are</c>, <c>act as if</c>, bare <c>jailbreak</c> — that fire on
    /// ordinary text; a default-on control which blocks those gets switched off, which is worse than
    /// missing them. Anything needing context stays semantic-only.
    /// </para>
    /// </remarks>
    protected virtual Regex? FastPathPattern => null;

    /// <summary>Whether this detector has a rule layer, and therefore fires without an embedding
    /// generator. Used by the documentation guard so the coverage tables cannot claim a control is
    /// inactive in a default install when it is not.</summary>
    public bool HasRuleFastPath => FastPathPattern is not null;

    /// <summary>Severity reported when <see cref="FastPathPattern"/> matches.</summary>
    protected virtual Severity FastPathSeverity => HighSeverity;

    /// <summary>Extracts the text to embed from the context. Override to scan a specific message role.</summary>
    protected virtual string GetText(SentinelContext ctx) => ctx.TextContent;

    /// <summary>Text the rule layer examines: the newest message, and only when it is incoming input.</summary>
    /// <remarks>
    /// Deliberately not <see cref="SentinelContext.TextContent"/>, which joins the whole conversation.
    /// The pipeline receives the full history every turn, so a rule match on an early message would
    /// re-match on every later one and block the session permanently, with no recovery short of
    /// truncating history. Similarity scores dilute as a conversation grows; an exact match never does.
    /// <para>
    /// Restricted to <see cref="ChatRole.User"/> because a literal-phrase rule cannot tell an attack
    /// from a quotation of one. Applied to the response leg it blocks a model refusal that echoes the
    /// phrase, and applied to tool results it blocks an agent for reading security documentation —
    /// this repository's own README contains the phrase. Prompt injection is about instructions
    /// arriving as input; injection carried in retrieved content is SEC-09's job, where semantic
    /// scoring can weigh context. The semantic path still covers every leg.
    /// </para>
    /// </remarks>
    protected virtual string GetFastPathText(SentinelContext ctx)
    {
        if (ctx.Messages.Count == 0) return string.Empty;

        var newest = ctx.Messages[ctx.Messages.Count - 1];
        return newest.Role == ChatRole.User ? newest.Text ?? string.Empty : string.Empty;
    }

    public async ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = GetText(ctx);
        if (string.IsNullOrWhiteSpace(text))
            return DetectionResult.Clean(Id);

        // Rule layer first: it needs no generator, so it works in a default install, and it saves a
        // round-trip on the unambiguous cases when a generator is configured.
        if (FastPathPattern is { } pattern)
        {
            var match = pattern.Match(GetFastPathText(ctx));
            if (match.Success)
            {
                return DetectionResult.WithSeverity(Id, FastPathSeverity, $"Rule match — '{Sanitise(match.Value)}'");
            }
        }

        if (_generator is null)
            return DetectionResult.Clean(Id);

        await EnsureInitializedAsync(ct).ConfigureAwait(false);

        var vector = await GetEmbeddingAsync(text, ct).ConfigureAwait(false);

        if (_highVectors is { Length: > 0 } && MaxSimilarity(vector.Span, _highVectors) >= HighThreshold)
            return DetectionResult.WithSeverity(Id, HighSeverity, "Semantic match — high-severity threat pattern");
        if (_mediumVectors is { Length: > 0 } && MaxSimilarity(vector.Span, _mediumVectors) >= MediumThreshold)
            return DetectionResult.WithSeverity(Id, MediumSeverity, "Semantic match — medium-severity threat pattern");
        if (_lowVectors is { Length: > 0 } && MaxSimilarity(vector.Span, _lowVectors) >= LowThreshold)
            return DetectionResult.WithSeverity(Id, LowSeverity, "Semantic match — low-severity threat pattern");

        return DetectionResult.Clean(Id);
    }

    /// <summary>Collapses whitespace and truncates matched text before it reaches a reason string.
    /// The match is attacker-controlled and every whitespace class in these patterns spans newlines,
    /// so an unsanitised value could forge extra lines in report output that prints one finding per
    /// line.</summary>
    private static string Sanitise(string value)
    {
        const int MaxLength = 120;
        var collapsed = new System.Text.StringBuilder(Math.Min(value.Length, MaxLength));
        var lastWasSpace = false;
        foreach (var c in value)
        {
            if (collapsed.Length >= MaxLength) break;

            if (char.IsWhiteSpace(c) || char.IsControl(c))
            {
                if (!lastWasSpace) collapsed.Append(' ');
                lastWasSpace = true;
                continue;
            }

            collapsed.Append(c);
            lastWasSpace = false;
        }

        return collapsed.ToString().Trim();
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

        if (_exampleCache is null)
        {
            var direct = await _generator!.GenerateAsync(examples, cancellationToken: ct).ConfigureAwait(false);
            return [.. direct.Select(e => e.Vector)];
        }

        // Embed only what the cache is missing. A warm persistent cache turns this whole method into
        // lookups, which is what makes semantic detection affordable in a per-invocation host.
        var vectors = new ReadOnlyMemory<float>[examples.Length];
        var missingText = new List<string>();
        var missingIndex = new List<int>();

        for (var i = 0; i < examples.Length; i++)
        {
            if (_exampleCache.TryGet(examples[i], out var hit))
            {
                vectors[i] = hit.Vector;
            }
            else
            {
                missingText.Add(examples[i]);
                missingIndex.Add(i);
            }
        }

        if (missingText.Count > 0)
        {
            var fresh = await _generator!.GenerateAsync(missingText, cancellationToken: ct).ConfigureAwait(false);
            if (fresh.Count != missingText.Count)
            {
                // A provider that batches, dedupes or drops inputs would otherwise pair vectors with
                // the wrong phrases and persist them under the wrong keys.
                throw new InvalidOperationException(
                    $"Embedding generator returned {fresh.Count} vectors for {missingText.Count} inputs; results must correspond one-to-one and in order.");
            }

            for (var i = 0; i < missingIndex.Count; i++)
            {
                _exampleCache.Set(missingText[i], fresh[i]);
                vectors[missingIndex[i]] = fresh[i].Vector;
            }
        }

        return vectors;
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
