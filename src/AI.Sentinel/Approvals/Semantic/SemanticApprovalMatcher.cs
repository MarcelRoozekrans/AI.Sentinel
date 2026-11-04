using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Approvals.Semantic;

/// <summary>Scores the text of a covered tool call against the semantic approval examples.</summary>
/// <remarks>Each selected text is embedded once, through the scope's scan cache, and compared to every example
/// by cosine similarity; the call's score is the maximum. The example vectors are embedded once per generator
/// and shared by concurrent first calls. Any embedding failure, including an empty vector or vectors of
/// different lengths, is a <see cref="SemanticMatch.Failed"/>; cancellation of the caller's token propagates.</remarks>
internal sealed class SemanticApprovalMatcher
{
    private const string DimensionMismatch = "dimension mismatch";
    private const string EmptyVector = "empty vector";

    private readonly EmbeddingScope _scope;
    private readonly (string Pattern, SemanticApprovalSpec Spec)[] _tools;
    private readonly string[] _examples;
    private readonly float? _threshold;
    private readonly int _maxBytes;
    private readonly GeneratorSharedTask<ReadOnlyMemory<float>[]> _exampleTask = new();

    /// <param name="scope">The generator and caches to embed with.</param>
    /// <param name="settings">The global settings; copied, so later changes do not affect this matcher.</param>
    /// <param name="tools">The covered tool patterns and their specs, in config order.</param>
    /// <param name="maxBytes">The UTF-8 byte cap per scored text.</param>
    /// <exception cref="ArgumentException">The settings replace the built-in examples but add none.</exception>
    public SemanticApprovalMatcher(
        EmbeddingScope scope,
        SemanticApprovalSettings settings,
        IReadOnlyList<(string Pattern, SemanticApprovalSpec Spec)> tools,
        int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBytes);

        _examples = settings.ReplaceExamples
            ? [.. settings.AddedExamples]
            : [.. SemanticApprovalExamples.Default, .. settings.AddedExamples];
        if (_examples.Length == 0)
            throw new ArgumentException("Replacing the built-in examples requires at least one added example.", nameof(settings));

        _scope = scope;
        _tools = [.. tools];
        _threshold = settings.Threshold;
        _maxBytes = maxBytes;
    }

    /// <summary>Whether a configured pattern covers <paramref name="toolName"/>; the first match in config order wins.</summary>
    public bool Covers(string toolName, [NotNullWhen(true)] out string? key, [NotNullWhen(true)] out SemanticApprovalSpec? spec)
    {
        ArgumentNullException.ThrowIfNull(toolName);
        foreach (var (pattern, s) in _tools)
        {
            if (ToolCallPolicyBinding.Matches(pattern, toolName))
            {
                key = pattern;
                spec = s;
                return true;
            }
        }

        key = null;
        spec = null;
        return false;
    }

    /// <summary>Scores the call of <paramref name="toolName"/> with <paramref name="args"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="toolName"/> is not covered.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> was cancelled.</exception>
    public async ValueTask<SemanticMatch> MatchAsync(string toolName, JsonElement args, CancellationToken ct)
    {
        if (!Covers(toolName, out var key, out var spec))
            throw new ArgumentException($"No semantic approval covers the tool '{toolName}'.", nameof(toolName));
        ct.ThrowIfCancellationRequested();

        var texts = SemanticApprovalText.Select(toolName, args, spec.ParsedPaths, _maxBytes);
        if (texts.Count == 0)
            return new SemanticMatch.NotFlagged(key, spec);

        var truncated = false;
        var inputs = new string[texts.Count];
        for (var i = 0; i < texts.Count; i++)
        {
            inputs[i] = texts[i].Text;
            truncated |= texts[i].Truncated;
        }

        ReadOnlyMemory<float>[] examples;
        ScanEmbeddings embeddings;
        try
        {
            examples = await _exampleTask.GetAsync(
                _scope.Generator, this, static (m, token) => m.EmbedExamplesAsync(token), ct).ConfigureAwait(false);
            embeddings = await ScanEmbedder.EmbedAsync(_scope, inputs, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // A provider often surfaces a cancellation as its own exception type; cancellation wins.
            ct.ThrowIfCancellationRequested();
            var kind = ex is VectorShapeException shape ? shape.Kind : ex.GetType().Name;
            return new SemanticMatch.Failed(key, spec, kind, truncated);
        }

        if (embeddings.FailedCount > 0)
        {
            var kind = embeddings.FirstFailure?.GetType().Name ?? nameof(InvalidOperationException);
            return new SemanticMatch.Failed(key, spec, kind, truncated);
        }

        return Score(key, spec, texts, inputs, embeddings, examples, truncated);
    }

    private SemanticMatch Score(
        string key, SemanticApprovalSpec spec, IReadOnlyList<ScoredText> texts, string[] inputs,
        ScanEmbeddings embeddings, ReadOnlyMemory<float>[] examples, bool truncated)
    {
        var dimensions = examples[0].Length;
        var best = -1f;
        var bestText = 0;
        var bestExample = 0;
        for (var i = 0; i < texts.Count; i++)
        {
            if (!embeddings.TryGet(inputs[i], out var vector) || vector.IsEmpty)
                return new SemanticMatch.Failed(key, spec, EmptyVector, truncated);
            if (vector.Length != dimensions)
                return new SemanticMatch.Failed(key, spec, DimensionMismatch, truncated);

            var index = SemanticDetectorBase.MaxSimilarityIndex(vector.Span, examples, out var score);
            if (score > best)
            {
                best = score;
                bestText = i;
                bestExample = Math.Max(index, 0);
            }
        }

        var threshold = spec.Threshold ?? _threshold ?? SemanticApprovalExamples.DefaultThreshold;
        return best >= threshold
            ? new SemanticMatch.Flagged(key, spec, best, threshold, texts[bestText].Path, _examples[bestExample], truncated)
            : new SemanticMatch.NotFlagged(key, spec);
    }

    // Throws instead of returning bad vectors, so the shared task is dropped and the next call embeds again.
    private async Task<ReadOnlyMemory<float>[]> EmbedExamplesAsync(CancellationToken ct)
    {
        var vectors = await ExampleEmbedder.EmbedAsync(_scope.Generator, _scope.ExampleCache, _examples, ct).ConfigureAwait(false);
        if (vectors.Length != _examples.Length)
        {
            throw new InvalidOperationException(
                $"Embedding generator returned {vectors.Length} vectors for {_examples.Length} inputs; results must correspond one-to-one and in order.");
        }

        var dimensions = vectors[0].Length;
        foreach (var vector in vectors)
        {
            if (vector.IsEmpty)
                throw new VectorShapeException(EmptyVector);
            if (vector.Length != dimensions)
                throw new VectorShapeException(DimensionMismatch);
        }

        return vectors;
    }

    /// <summary>The example vectors cannot be compared: empty, or not all the same length.</summary>
    private sealed class VectorShapeException(string kind) : Exception($"The example embeddings have a bad shape: {kind}.")
    {
        public string Kind { get; } = kind;
    }
}
