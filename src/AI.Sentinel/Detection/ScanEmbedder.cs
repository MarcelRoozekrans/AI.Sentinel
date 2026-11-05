using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Embeds a scan's distinct texts once: one batch call, then per-input retries if it fails.</summary>
/// <remarks>An <see cref="OperationCanceledException"/> is cancellation only when the caller's token is cancelled.
/// Otherwise it is a provider failure: HttpClient reports its timeout that way. A vector that cannot be scored
/// (empty, zero-norm, non-finite or of the wrong length) counts as a failed text and is never cached; a cached one
/// is embedded again. Such a bad answer is not an outage, so it does not feed the cut-off.</remarks>
internal static class ScanEmbedder
{
    // Two failures before any success read as an outage, not a bad input, so the rest are not tried.
    private const int OutageFailures = 2;

    public static async Task<ScanEmbeddings> EmbedAsync(
        EmbeddingScope scope, IReadOnlyCollection<string> texts, int? expectedDimension, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Without an expected length the first usable vector sets it, so one scan never mixes lengths.
        var dimension = new Dimension(expectedDimension);

        var vectors = new Dictionary<string, ReadOnlyMemory<float>>(StringComparer.Ordinal);
        var misses = new List<string>();
        foreach (var text in texts)
        {
            if (scope.ScanCache.TryGet(text, out var cached) && dimension.Check(cached.Vector.Span) is null)
            {
                vectors[text] = cached.Vector;
            }
            else
            {
                misses.Add(text);
            }
        }

        if (misses.Count == 0)
        {
            return new ScanEmbeddings(vectors, texts.Count, 0, null);
        }

        var (batchFailure, batchOk, unusable, unusableFailure) =
            await TryBatchAsync(scope, misses, vectors, dimension, ct).ConfigureAwait(false);
        if (batchOk)
        {
            return new ScanEmbeddings(vectors, texts.Count, unusable, unusableFailure);
        }

        // A single miss was the whole batch, so retrying it would repeat the same call. A batch that timed out
        // reads as an outage: retrying each input would wait out one timeout per input.
        if (misses.Count == 1 || batchFailure is OperationCanceledException)
        {
            return new ScanEmbeddings(vectors, texts.Count, misses.Count, batchFailure);
        }

        var (failed, firstFailure) =
            await RetryEachAsync(scope, misses, vectors, dimension, batchFailure, ct).ConfigureAwait(false);
        return new ScanEmbeddings(vectors, texts.Count, failed, firstFailure);
    }

    private static async Task<(Exception? Failure, bool Ok, int Unusable, InvalidEmbeddingException? UnusableFailure)> TryBatchAsync(
        EmbeddingScope scope, List<string> misses, Dictionary<string, ReadOnlyMemory<float>> vectors, Dimension dimension,
        CancellationToken ct)
    {
        try
        {
            var batch = await scope.Generator.GenerateAsync(misses, cancellationToken: ct).ConfigureAwait(false);
            if (batch.Count != misses.Count)
            {
                return (CountMismatch(misses.Count, batch.Count), false, 0, null);
            }
            var unusable = 0;
            InvalidEmbeddingException? unusableFailure = null;
            for (var i = 0; i < misses.Count; i++)
            {
                // The batch itself worked, so an unusable vector fails only its text and nothing is retried.
                if (Store(scope, vectors, dimension, misses[i], batch[i]) is { } problem)
                {
                    unusable++;
                    unusableFailure ??= problem;
                }
            }
            return (null, true, unusable, unusableFailure);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // A provider often surfaces a cancellation as its own exception type; cancellation wins.
            ct.ThrowIfCancellationRequested();
            return (ex, false, 0, null);
        }
    }

    private static async Task<(int Failed, Exception? FirstFailure)> RetryEachAsync(
        EmbeddingScope scope, List<string> misses, Dictionary<string, ReadOnlyMemory<float>> vectors,
        Dimension dimension, Exception? firstFailure, CancellationToken ct)
    {
        var failed = 0;
        var unusable = 0;
        var succeeded = 0;
        foreach (var text in misses)
        {
            ct.ThrowIfCancellationRequested();
            if (failed >= OutageFailures && succeeded == 0)
            {
                failed++;
                continue;
            }

            try
            {
                var single = await scope.Generator.GenerateAsync([text], cancellationToken: ct).ConfigureAwait(false);
                if (single.Count != 1)
                {
                    throw CountMismatch(1, single.Count);
                }
                if (Store(scope, vectors, dimension, text, single[0]) is { } problem)
                {
                    // A bad answer, not an outage: it must not feed the cut-off.
                    unusable++;
                    firstFailure ??= problem;
                    continue;
                }
                succeeded++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                ct.ThrowIfCancellationRequested();
                failed++;
                // The batch exception stays the first failure; it is the most representative of the outage.
                firstFailure ??= ex;
            }
        }

        return (failed + unusable, firstFailure);
    }

    // Caches and returns only a usable vector. The failure is returned, not thrown, and never names the text.
    private static InvalidEmbeddingException? Store(
        EmbeddingScope scope, Dictionary<string, ReadOnlyMemory<float>> vectors, Dimension dimension,
        string text, Embedding<float> embedding)
    {
        if (dimension.Check(embedding.Vector.Span) is { } problem)
        {
            return new InvalidEmbeddingException(problem);
        }
        scope.ScanCache.Set(text, embedding);
        vectors[text] = embedding.Vector;
        return null;
    }

    // The length every vector of one scan must have. The first usable vector fixes it when none was given.
    private sealed class Dimension(int? expected)
    {
        private int? _expected = expected;

        public string? Check(ReadOnlySpan<float> vector)
        {
            if (InvalidEmbeddingException.Problem(vector) is { } problem)
            {
                return problem;
            }
            if (_expected is { } length && vector.Length != length)
            {
                return InvalidEmbeddingException.DimensionMismatch;
            }
            _expected ??= vector.Length;
            return null;
        }
    }

    // Counts only: the message must never carry an input text.
    private static InvalidOperationException CountMismatch(int expected, int actual) =>
        new($"The embedding generator returned {actual} vectors for {expected} inputs.");
}
