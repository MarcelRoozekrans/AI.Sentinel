using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Approvals.Semantic;

/// <summary>Scores the text of a covered tool call against the semantic approval examples.</summary>
/// <remarks>Each selected text is embedded once, through the scope's scan cache, and compared to every example
/// by cosine similarity; the call's score is the maximum. The example vectors are embedded once per generator
/// and shared by concurrent first calls. Any embedding failure, including an empty vector or vectors of
/// different lengths, a zero-norm or a non-finite vector, is a <see cref="SemanticMatch.Failed"/>, and so are
/// arguments whose text cannot be read: an escape that does not decode or a duplicate key on a selected path.
/// Cancellation of the caller's token propagates.</remarks>
internal sealed class SemanticApprovalMatcher
{
    // A text the embedder reported as done but returned no vector for.
    private const string MissingVector = "missing vector";

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

    /// <summary>Scores the call of <paramref name="toolName"/> with <paramref name="args"/>, under the
    /// <paramref name="key"/> and <paramref name="spec"/> that <see cref="Covers"/> resolved for it.</summary>
    /// <remarks>Never throws for a provider or input problem: any such exception is a <see cref="SemanticMatch.Failed"/>.</remarks>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> was cancelled.</exception>
    public async ValueTask<SemanticMatch> MatchAsync(
        string toolName, JsonElement args, string key, SemanticApprovalSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(toolName);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(spec);
        ct.ThrowIfCancellationRequested();

        var truncated = false;
        try
        {
            var texts = SemanticApprovalText.Select(toolName, args, spec.ParsedPaths, _maxBytes);
            if (texts.Count == 0)
                return new SemanticMatch.NotFlagged(key, spec);

            var inputs = new string[texts.Count];
            for (var i = 0; i < texts.Count; i++)
            {
                inputs[i] = texts[i].Text;
                truncated |= texts[i].Truncated;
            }

            var examples = await _exampleTask.GetAsync(
                _scope.Generator, this, static (m, token) => m.EmbedExamplesAsync(token), ct).ConfigureAwait(false);
            var embeddings = await ScanEmbedder.EmbedAsync(_scope, inputs, examples[0].Length, ct).ConfigureAwait(false);
            if (embeddings.FailedCount > 0)
            {
                var kind = embeddings.FirstFailure switch
                {
                    InvalidEmbeddingException invalid => invalid.Kind,
                    { } failure => failure.GetType().Name,
                    _ => nameof(InvalidOperationException),
                };
                return new SemanticMatch.Failed(key, spec, kind, truncated);
            }

            return Score(key, spec, texts, inputs, embeddings, examples, truncated);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // A provider often surfaces a cancellation as its own exception type; cancellation wins.
            ct.ThrowIfCancellationRequested();
            var kind = ex switch
            {
                InvalidEmbeddingException invalid => invalid.Kind,
                SemanticTextException text => text.Kind,
                _ => ex.GetType().Name,
            };
            return new SemanticMatch.Failed(key, spec, kind, truncated);
        }
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
            if (!embeddings.TryGet(inputs[i], out var vector))
                return new SemanticMatch.Failed(key, spec, MissingVector, truncated);
            if (InvalidEmbeddingException.Problem(vector.Span) is { } problem)
                return new SemanticMatch.Failed(key, spec, problem, truncated);
            if (vector.Length != dimensions)
                return new SemanticMatch.Failed(key, spec, InvalidEmbeddingException.DimensionMismatch, truncated);

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

    // ExampleEmbedder throws on an unusable response, so the shared task is dropped and the next call embeds again.
    private Task<ReadOnlyMemory<float>[]> EmbedExamplesAsync(CancellationToken ct) =>
        ExampleEmbedder.EmbedAsync(_scope.Generator, _scope.ExampleCache, _examples, ct);
}
