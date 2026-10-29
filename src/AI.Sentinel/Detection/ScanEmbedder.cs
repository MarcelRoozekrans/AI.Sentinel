using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Embeds a scan's distinct texts once: one batch call, then per-input retries if it fails.</summary>
internal static class ScanEmbedder
{
    // Two failures before any success read as an outage, not a bad input, so the rest are not tried.
    private const int OutageFailures = 2;

    public static async Task<ScanEmbeddings> EmbedAsync(
        EmbeddingScope scope, IReadOnlyCollection<string> texts, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var vectors = new Dictionary<string, ReadOnlyMemory<float>>(StringComparer.Ordinal);
        var misses = new List<string>();
        foreach (var text in texts)
        {
            if (scope.ScanCache.TryGet(text, out var cached))
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

        var (batchFailure, batchOk) = await TryBatchAsync(scope, misses, vectors, ct).ConfigureAwait(false);
        if (batchOk)
        {
            return new ScanEmbeddings(vectors, texts.Count, 0, null);
        }

        // A single miss was the whole batch, so retrying it would repeat the same call.
        if (misses.Count == 1)
        {
            return new ScanEmbeddings(vectors, texts.Count, 1, batchFailure);
        }

        var (failed, firstFailure) = await RetryEachAsync(scope, misses, vectors, batchFailure, ct).ConfigureAwait(false);
        return new ScanEmbeddings(vectors, texts.Count, failed, firstFailure);
    }

    private static async Task<(Exception? Failure, bool Ok)> TryBatchAsync(
        EmbeddingScope scope, List<string> misses, Dictionary<string, ReadOnlyMemory<float>> vectors, CancellationToken ct)
    {
        try
        {
            var batch = await scope.Generator.GenerateAsync(misses, cancellationToken: ct).ConfigureAwait(false);
            if (batch.Count != misses.Count)
            {
                return (CountMismatch(misses.Count, batch.Count), false);
            }
            for (var i = 0; i < misses.Count; i++)
            {
                Store(scope, vectors, misses[i], batch[i]);
            }
            return (null, true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested)
        {
            return (ex, false);
        }
    }

    private static async Task<(int Failed, Exception? FirstFailure)> RetryEachAsync(
        EmbeddingScope scope, List<string> misses, Dictionary<string, ReadOnlyMemory<float>> vectors,
        Exception? firstFailure, CancellationToken ct)
    {
        var failed = 0;
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
                Store(scope, vectors, text, single[0]);
                succeeded++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested)
            {
                failed++;
                // The batch exception stays the first failure; it is the most representative of the outage.
                firstFailure ??= ex;
            }
        }

        return (failed, firstFailure);
    }

    private static void Store(EmbeddingScope scope, Dictionary<string, ReadOnlyMemory<float>> vectors, string text, Embedding<float> embedding)
    {
        scope.ScanCache.Set(text, embedding);
        vectors[text] = embedding.Vector;
    }

    // Counts only: the message must never carry an input text.
    private static InvalidOperationException CountMismatch(int expected, int actual) =>
        new($"The embedding generator returned {actual} vectors for {expected} inputs.");
}
