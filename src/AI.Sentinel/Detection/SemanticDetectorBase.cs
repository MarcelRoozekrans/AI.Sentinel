using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.Extensions.AI;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>Base class for embedding-based semantic threat detectors.</summary>
/// <remarks>
/// Subclasses declare <see cref="HighExamples"/>, <see cref="MediumExamples"/>, and
/// <see cref="LowExamples"/> representative phrases. At first scan, all examples are
/// embedded via <see cref="Microsoft.Extensions.AI.IEmbeddingGenerator{TInput,TEmbedding}"/>
/// and cached in-process, once per generator instance: concurrent first scans share one embedding of them,
/// and a failed attempt is retried on the next scan.
/// <para>
/// Each scan scores the messages that are new in it, from <see cref="SentinelContext.NewMessagesFrom"/> on,
/// one by one: the non-blank ones, at most 16, with redaction placeholders such as
/// <c>[EMAIL_1_k3f9x2]</c> normalised to <c>[EMAIL]</c>. Past 16, the oldest are joined into one text. A message's text is its <see cref="ChatMessage.Text"/>
/// plus the tool calls and tool results it carries, the same text the rule-based detectors judge: see
/// <see cref="SentinelContext.TextContent"/>. Each text is embedded and compared by
/// cosine similarity against the reference vectors; for each text the first bucket, High, then Medium, then Low,
/// whose max similarity reaches its threshold gives a severity, and the most severe of those is reported.
/// Override <see cref="GetTextsToScore"/> to choose other texts.
/// </para>
/// <para>
/// In a pipeline, the texts of all its semantic detectors are merged and each distinct one is embedded once per
/// scan, in one batch, with the pipeline's generator and caches; a named pipeline uses its own generator when it
/// sets one, otherwise the default pipeline's. A text the provider rejects is skipped by itself, the endpoint is
/// treated as down after two single-input failures with no success, and a failure is reported once per scan. A
/// detector left with no vectors returns <see cref="DetectionResult.Clean"/>, but one whose example phrases
/// failed still runs its rule layer. Called directly, outside a pipeline, a detector embeds with the generator and
/// caches of the <see cref="SentinelOptions"/> it was constructed with.
/// </para>
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
    // Keyed by generator instance, never by value: vectors from one generator must not be compared with another's,
    // and once nothing references a generator, the table releases its vectors.
    private readonly ConditionalWeakTable<IEmbeddingGenerator<string, Embedding<float>>, ExampleSlot> _exampleSlots = new();
    private readonly bool _overridesGetText;

    protected SemanticDetectorBase(SentinelOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _generator = options.EmbeddingGenerator;
        _cache = options.EmbeddingCache ?? new InMemoryLruEmbeddingCache();
        _exampleCache = options.ExampleEmbeddingCache;

        // A delegate to a virtual method binds to the most derived override, so its declaring type tells whether a
        // subclass overrides the pre-3.1 hook. Comparing the returned string with TextContent cannot: on a
        // one-message context string.Join returns that message's own instance.
#pragma warning disable SENTINEL001
        _overridesGetText = new Func<SentinelContext, string>(GetText).Method.DeclaringType != typeof(SemanticDetectorBase);
#pragma warning restore SENTINEL001
    }

    public abstract DetectorId Id { get; }
    public abstract DetectorCategory Category { get; }

    /// <inheritdoc cref="IDetector.EnabledByDefault"/>
    /// <remarks>Declared here, not left to the interface's default, so a subclass can override it: a class
    /// member only implements an interface member for the class that lists the interface.</remarks>
    public virtual bool EnabledByDefault => true;

    /// <summary>Representative phrases that indicate a high-severity threat.</summary>
    protected abstract string[] HighExamples { get; }
    /// <summary>Representative phrases that indicate a medium-severity threat.</summary>
    protected abstract string[] MediumExamples { get; }
    /// <summary>Representative phrases that indicate a low-severity threat.</summary>
    protected abstract string[] LowExamples { get; }

    /// <summary>Severity returned when the High bucket threshold is exceeded. Defaults to <see cref="Severity.High"/>.</summary>
    protected virtual Severity HighSeverity => Severity.High;
    /// <summary>Severity returned when the Medium bucket threshold is exceeded. Defaults to <see cref="Severity.Medium"/>.</summary>
    protected virtual Severity MediumSeverity => Severity.Medium;
    /// <summary>Severity returned when the Low bucket threshold is exceeded. Defaults to <see cref="Severity.Low"/>.</summary>
    protected virtual Severity LowSeverity => Severity.Low;

    protected virtual float HighThreshold => 0.90f;
    protected virtual float MediumThreshold => 0.82f;
    protected virtual float LowThreshold => 0.75f;

    /// <summary>The High threshold <paramref name="configuration"/> sets, or this detector's built-in one.</summary>
    internal float EffectiveHighThreshold(DetectorConfiguration? configuration) => configuration?.HighThreshold ?? HighThreshold;

    /// <summary>The Medium threshold <paramref name="configuration"/> sets, or this detector's built-in one.</summary>
    internal float EffectiveMediumThreshold(DetectorConfiguration? configuration) => configuration?.MediumThreshold ?? MediumThreshold;

    /// <summary>Throws when <paramref name="configuration"/>, filled in with this detector's built-in values, puts
    /// the Medium threshold above the High one. Only the instance knows the built-in value of a threshold left unset.</summary>
    internal void ThrowIfMediumAboveHigh(DetectorConfiguration? configuration)
    {
        var high = EffectiveHighThreshold(configuration);
        var medium = EffectiveMediumThreshold(configuration);
        if (medium > high)
        {
            throw new InvalidOperationException(
                $"AI.Sentinel: detector {GetType().Name} has MediumThreshold {medium} above HighThreshold {high}. Medium must not exceed High.");
        }
    }

    /// <summary>The High examples, for the offline threshold evaluation in <c>tools/AI.Sentinel.ComplianceEval</c>.</summary>
    internal string[] EvaluationHighExamples => HighExamples;
    /// <summary>The Medium examples, for the offline threshold evaluation.</summary>
    internal string[] EvaluationMediumExamples => MediumExamples;
    /// <summary>The High threshold, for the offline threshold evaluation.</summary>
    internal float EvaluationHighThreshold => HighThreshold;
    /// <summary>The Medium threshold, for the offline threshold evaluation.</summary>
    internal float EvaluationMediumThreshold => MediumThreshold;
    /// <summary>The Low examples, for the offline threshold evaluation.</summary>
    internal string[] EvaluationLowExamples => LowExamples;
    /// <summary>The Low threshold, for the offline threshold evaluation.</summary>
    internal float EvaluationLowThreshold => LowThreshold;
    /// <summary>The severity of the High bucket, for the offline threshold evaluation.</summary>
    internal Severity EvaluationHighSeverity => HighSeverity;
    /// <summary>The severity of the Medium bucket, for the offline threshold evaluation.</summary>
    internal Severity EvaluationMediumSeverity => MediumSeverity;
    /// <summary>The severity of the Low bucket, for the offline threshold evaluation.</summary>
    internal Severity EvaluationLowSeverity => LowSeverity;

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

    /// <summary>The most texts one scan embeds. Past it, the oldest texts are joined into the first one.</summary>
    internal const int MaxMessagesToScore = 16;

    /// <summary>Extracts the text to embed from the context. Override to scan a specific message role.</summary>
    /// <remarks>Before 3.1 this was the one text of the scan, by default the whole conversation joined. An override
    /// is still honoured: <see cref="GetTextsToScore"/> scores what it returns as the only text.</remarks>
    [Obsolete("Semantic detectors score each new message since 3.1. Override GetTextsToScore instead; an override of GetText is still scored as the one text of the scan.",
        DiagnosticId = "SENTINEL001",
        UrlFormat = "https://marcelroozekrans.github.io/AI.Sentinel/docs/detectors/overview#how-semantic-detectors-score")]
    protected virtual string GetText(SentinelContext ctx) => ctx.TextContent;

    /// <summary>The texts this scan scores, oldest first. By default, the text of each new message, from
    /// <see cref="SentinelContext.NewMessagesFrom"/> to the end: its <see cref="ChatMessage.Text"/> plus the tool calls
    /// and tool results it carries, as <see cref="SentinelContext.TextContent"/> describes.</summary>
    /// <remarks>Override to score, for example, one role only. Blank texts and duplicates are skipped. At most
    /// 16 texts are embedded: past that, the oldest are joined into one.</remarks>
    protected virtual IEnumerable<string> GetTextsToScore(SentinelContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        if (_overridesGetText)
        {
            // Honours a legacy GetText override: what it returns is scored as the one text of the scan.
#pragma warning disable SENTINEL001
            return [GetText(ctx)];
#pragma warning restore SENTINEL001
        }

        return NewMessageTexts(ctx);
    }

    private static IEnumerable<string> NewMessageTexts(SentinelContext ctx)
    {
        for (var i = ctx.NewMessagesFrom; i < ctx.Messages.Count; i++)
        {
            yield return SentinelContext.MessageText(ctx.Messages[i]);
        }
    }

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

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
        AnalyzeAsync(ctx, configuration: null, ct);

    /// <summary>Analyzes with the thresholds of the pipeline that runs this detector.</summary>
    /// <remarks>One detector instance is shared by every named pipeline, so a pipeline's
    /// <see cref="DetectorConfiguration.HighThreshold"/> and <see cref="DetectorConfiguration.MediumThreshold"/>
    /// arrive with each call from <see cref="DetectionPipeline"/> instead of being stored on the detector.</remarks>
    internal async ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, DetectorConfiguration? configuration, CancellationToken ct)
    {
        if (EarlyResult(ctx) is { } early)
            return early;

        if (_generator is null)
            return DetectionResult.Clean(Id);

        var texts = SelectTextsToScore(ctx);
        if (texts.Count == 0)
            return DetectionResult.Clean(Id);

        var examples = await GetExampleVectorsAsync(_generator, _exampleCache, ct).ConfigureAwait(false);

        var vectors = await GetEmbeddingsAsync(texts, ct).ConfigureAwait(false);

        return Score(vectors, examples, configuration);
    }

    /// <summary>Analyzes with the scope and the scan vectors of the pipeline that runs this detector.</summary>
    /// <remarks>The pipeline embedded the texts of every semantic detector in <paramref name="scan"/> once, so this
    /// overload never calls the generator for scan texts: it only awaits the example vectors of
    /// <paramref name="scope"/>'s generator. <paramref name="texts"/> is what <see cref="TextsToEmbed"/> returned for
    /// this scan, so an override of <see cref="GetTextsToScore"/> runs once and the texts scored are the texts
    /// embedded. A text that is not in <paramref name="scan"/> could not be embedded and is skipped; the pipeline has
    /// reported it.</remarks>
    internal async ValueTask<DetectionResult> AnalyzeAsync(
        SentinelContext ctx, DetectorConfiguration? configuration, EmbeddingScope scope, ScanEmbeddings scan,
        IReadOnlyList<string> texts, CancellationToken ct)
    {
        if (EarlyResult(ctx) is { } early)
            return early;

        if (texts.Count == 0)
            return DetectionResult.Clean(Id);

        var examples = await GetExampleVectorsAsync(scope.Generator, scope.ExampleCache, ct).ConfigureAwait(false);

        var vectors = new List<ReadOnlyMemory<float>>(texts.Count);
        foreach (var text in texts)
        {
            if (scan.TryGet(text, out var vector)) vectors.Add(vector);
        }

        return Score(vectors, examples, configuration);
    }

    /// <summary>The texts the pipeline embeds for this detector in a scan: those it will score, or none when a legacy
    /// <c>GetText</c> override returns blank.</summary>
    internal IReadOnlyList<string> TextsToEmbed(SentinelContext ctx)
    {
#pragma warning disable SENTINEL001
        if (_overridesGetText && string.IsNullOrWhiteSpace(GetText(ctx)))
            return [];
#pragma warning restore SENTINEL001

        return SelectTextsToScore(ctx);
    }

    /// <summary>The result of the rule layer alone, or <see cref="DetectionResult.Clean"/>. For a scan whose example
    /// vectors could not be embedded: the rule layer needs none.</summary>
    internal DetectionResult AnalyzeRuleLayer(SentinelContext ctx) => EarlyResult(ctx) ?? DetectionResult.Clean(Id);

    /// <summary>The result decided before any embedding: Clean for a legacy blank opt-out, or a rule match.</summary>
    private DetectionResult? EarlyResult(SentinelContext ctx)
    {
        // As in 3.0, a legacy GetText override that returns blank opts the scan out, before the rule layer runs.
#pragma warning disable SENTINEL001
        if (_overridesGetText && string.IsNullOrWhiteSpace(GetText(ctx)))
            return DetectionResult.Clean(Id);
#pragma warning restore SENTINEL001

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

        return null;
    }

    /// <summary>The most severe bucket any of <paramref name="vectors"/> reaches, or Clean.</summary>
    private DetectionResult Score(IEnumerable<ReadOnlyMemory<float>> vectors, ExampleVectors examples, DetectorConfiguration? configuration)
    {
        var highThreshold = EffectiveHighThreshold(configuration);
        var mediumThreshold = EffectiveMediumThreshold(configuration);
        var ceiling = Max(HighSeverity, Max(MediumSeverity, LowSeverity));
        var best = DetectionResult.Clean(Id);
        foreach (var vector in vectors)
        {
            var result = Classify(vector.Span, examples, highThreshold, mediumThreshold);
            if (result is not null && result.Severity > best.Severity)
            {
                best = result;
                if (best.Severity == ceiling) break;
            }
        }

        return best;
    }

    private static Severity Max(Severity a, Severity b) => a >= b ? a : b;

    /// <summary>The first bucket, High, then Medium, then Low, that <paramref name="vector"/> reaches, or
    /// <see langword="null"/>.</summary>
    private DetectionResult? Classify(ReadOnlySpan<float> vector, ExampleVectors examples, float highThreshold, float mediumThreshold)
    {
        if (examples.High is { Length: > 0 } && MaxSimilarity(vector, examples.High) >= highThreshold)
            return DetectionResult.WithSeverity(Id, HighSeverity, "Semantic match — high-severity threat pattern");
        if (examples.Medium is { Length: > 0 } && MaxSimilarity(vector, examples.Medium) >= mediumThreshold)
            return DetectionResult.WithSeverity(Id, MediumSeverity, "Semantic match — medium-severity threat pattern");
        if (examples.Low is { Length: > 0 } && MaxSimilarity(vector, examples.Low) >= LowThreshold)
            return DetectionResult.WithSeverity(Id, LowSeverity, "Semantic match — low-severity threat pattern");

        return null;
    }

    /// <summary>The non-blank texts of <see cref="GetTextsToScore"/>, placeholders normalised, without duplicates,
    /// in order, at most 16. Past 16, the oldest are joined with a newline into the first text, so every text is
    /// still judged.</summary>
    /// <remarks>Dropping the oldest instead would let a tool result hide an injection in its first block by
    /// following it with 16 benign ones.</remarks>
    private List<string> SelectTextsToScore(SentinelContext ctx)
    {
        // Blank texts and duplicates are dropped before the cap, so they do not cost a text its own slot.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var texts = new List<string>();
        foreach (var text in GetTextsToScore(ctx))
        {
            if (string.IsNullOrWhiteSpace(text)) continue;

            var normalised = PlaceholderFormat.Normalise(text);
            if (seen.Add(normalised)) texts.Add(normalised);
        }

        if (texts.Count <= MaxMessagesToScore)
            return texts;

        // The oldest overflow plus the first kept text become one input, followed by the newest 15.
        var folded = texts.Count - MaxMessagesToScore + 1;
        var result = new List<string>(MaxMessagesToScore) { string.Join('\n', texts.GetRange(0, folded)) };
        result.AddRange(texts.GetRange(folded, texts.Count - folded));
        return result;
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

    /// <summary>The reference vectors of each severity bucket.</summary>
    internal sealed record ExampleVectors(
        ReadOnlyMemory<float>[] High,
        ReadOnlyMemory<float>[] Medium,
        ReadOnlyMemory<float>[] Low);

    private sealed class ExampleSlot
    {
#if NET9_0_OR_GREATER
        public readonly System.Threading.Lock Lock = new();
#else
        public readonly object Lock = new();
#endif
        public Task<ExampleVectors>? Task;
    }

    /// <summary>The example vectors for <paramref name="generator"/>, embedded on first use and shared by every
    /// later and concurrent caller with the same generator instance.</summary>
    /// <remarks>The first caller starts the embedding on its own token and the others await that task. A task
    /// that fails or is cancelled is dropped, so the next call retries. A waiter whose own token is cancelled
    /// stops waiting without touching the shared task. If the shared task was cancelled by another caller's
    /// token, this caller retries once with a task of its own.</remarks>
    internal async Task<ExampleVectors> GetExampleVectorsAsync(
        IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, CancellationToken ct)
    {
        var slot = _exampleSlots.GetValue(generator, static _ => new ExampleSlot());
        for (var attempt = 0; ; attempt++)
        {
            Task<ExampleVectors> task;
            TaskCompletionSource<ExampleVectors>? owned = null;
            lock (slot.Lock)
            {
                // A task that failed while every caller had already stopped waiting was never evicted by one.
                if (slot.Task is { IsCompleted: true, IsCompletedSuccessfully: false }) slot.Task = null;
                if (slot.Task is null)
                {
                    owned = new TaskCompletionSource<ExampleVectors>(TaskCreationOptions.RunContinuationsAsynchronously);
                    slot.Task = owned.Task;
                }
                task = slot.Task;
            }

            // Started outside the lock: the example cache lookups and a generator's synchronous prefix run here.
            if (owned is not null) _ = RunEmbeddingAsync(owned, generator, exampleCache, ct);

            try
            {
                return await task.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (Exception) when (task.IsCompleted && !task.IsCompletedSuccessfully)
            {
                lock (slot.Lock)
                {
                    if (ReferenceEquals(slot.Task, task)) slot.Task = null;
                }

                if (!(task.IsCanceled && !ct.IsCancellationRequested && attempt == 0)) throw;
            }
        }
    }

    /// <summary>The shared embedding task currently held for <paramref name="generator"/>. For tests.</summary>
    internal bool TryPeekExampleTask(
        IEmbeddingGenerator<string, Embedding<float>> generator, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Task<ExampleVectors>? task)
    {
        task = _exampleSlots.TryGetValue(generator, out var slot) ? slot.Task : null;
        return task is not null;
    }

    private async Task RunEmbeddingAsync(
        TaskCompletionSource<ExampleVectors> target,
        IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, CancellationToken ct)
    {
        try
        {
            target.TrySetResult(await EmbedAllExamplesAsync(generator, exampleCache, ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException ex)
        {
            target.TrySetCanceled(ex.CancellationToken);
        }
        catch (Exception ex)
        {
            target.TrySetException(ex);
        }
    }

    private async Task<ExampleVectors> EmbedAllExamplesAsync(
        IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, CancellationToken ct)
    {
        var high = await EmbedExamplesAsync(generator, exampleCache, HighExamples, ct).ConfigureAwait(false);
        var medium = await EmbedExamplesAsync(generator, exampleCache, MediumExamples, ct).ConfigureAwait(false);
        var low = await EmbedExamplesAsync(generator, exampleCache, LowExamples, ct).ConfigureAwait(false);
        return new ExampleVectors(high, medium, low);
    }

    private static async Task<ReadOnlyMemory<float>[]> EmbedExamplesAsync(
        IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, string[] examples, CancellationToken ct)
    {
        if (examples.Length == 0) return [];

        if (exampleCache is null)
        {
            var direct = await generator.GenerateAsync(examples, cancellationToken: ct).ConfigureAwait(false);
            return [.. direct.Select(e => e.Vector)];
        }

        // Embed only what the cache is missing. A warm persistent cache turns this whole method into
        // lookups, which is what makes semantic detection affordable in a per-invocation host.
        var vectors = new ReadOnlyMemory<float>[examples.Length];
        var missingText = new List<string>();
        var missingIndex = new List<int>();

        for (var i = 0; i < examples.Length; i++)
        {
            if (exampleCache.TryGet(examples[i], out var hit))
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
            var fresh = await generator.GenerateAsync(missingText, cancellationToken: ct).ConfigureAwait(false);
            if (fresh.Count != missingText.Count)
            {
                // A provider that batches, dedupes or drops inputs would otherwise pair vectors with
                // the wrong phrases and persist them under the wrong keys.
                throw new InvalidOperationException(
                    $"Embedding generator returned {fresh.Count} vectors for {missingText.Count} inputs; results must correspond one-to-one and in order.");
            }

            for (var i = 0; i < missingIndex.Count; i++)
            {
                exampleCache.Set(missingText[i], fresh[i]);
                vectors[missingIndex[i]] = fresh[i].Vector;
            }
        }

        return vectors;
    }

    /// <summary>The vector of each of <paramref name="texts"/>, in order: cached ones from the scan cache, and all
    /// misses from one generator call.</summary>
    private async Task<ReadOnlyMemory<float>[]> GetEmbeddingsAsync(IReadOnlyList<string> texts, CancellationToken ct)
    {
        var vectors = new ReadOnlyMemory<float>[texts.Count];
        var missingText = new List<string>();
        var missingIndex = new List<int>();

        for (var i = 0; i < texts.Count; i++)
        {
            if (_cache.TryGet(texts[i], out var cached))
            {
                vectors[i] = cached.Vector;
            }
            else
            {
                missingText.Add(texts[i]);
                missingIndex.Add(i);
            }
        }

        if (missingText.Count == 0) return vectors;

        var fresh = await _generator!.GenerateAsync(missingText, cancellationToken: ct).ConfigureAwait(false);
        if (fresh.Count != missingText.Count)
        {
            // A provider that batches, dedupes or drops inputs would otherwise pair vectors with the wrong
            // messages and cache them under the wrong keys.
            throw new InvalidOperationException(
                $"Embedding generator returned {fresh.Count} vectors for {missingText.Count} inputs; results must correspond one-to-one and in order.");
        }

        for (var i = 0; i < missingIndex.Count; i++)
        {
            _cache.Set(missingText[i], fresh[i]);
            vectors[missingIndex[i]] = fresh[i].Vector;
        }

        return vectors;
    }

    /// <summary>The highest cosine similarity between <paramref name="query"/> and any reference vector.
    /// Internal so the offline threshold evaluation scores with exactly this math.</summary>
    internal static float MaxSimilarity(ReadOnlySpan<float> query, ReadOnlyMemory<float>[] references)
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
            na += a[i] * a[i];
            nb += b[i] * b[i];
        }
        var denom = MathF.Sqrt(na) * MathF.Sqrt(nb);
        return denom > 0f ? dot / denom : 0f;
    }
}
