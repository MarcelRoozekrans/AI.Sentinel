using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Embeds reference phrases, using an optional persistent cache for the ones it already holds.</summary>
/// <remarks>Fresh vectors are checked before any is cached: a wrong count, an empty, zero-norm or non-finite vector,
/// or vectors of mixed lengths throw, so one bad provider response never poisons a persistent cache and the
/// caller's next attempt embeds again.</remarks>
internal static class ExampleEmbedder
{
    public static async Task<ReadOnlyMemory<float>[]> EmbedAsync(
        IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, string[] texts, CancellationToken ct)
    {
        if (texts.Length == 0) return [];

        if (exampleCache is null)
        {
            var direct = await generator.GenerateAsync(texts, cancellationToken: ct).ConfigureAwait(false);
            CheckCount(direct.Count, texts.Length);
            var all = direct.Select(e => e.Vector).ToArray();
            Validate(all);
            return all;
        }

        // Embed only what the cache is missing. A warm persistent cache turns this whole method into
        // lookups, which is what makes semantic detection affordable in a per-invocation host.
        var vectors = new ReadOnlyMemory<float>[texts.Length];
        var missingText = new List<string>();
        var missingIndex = new List<int>();

        for (var i = 0; i < texts.Length; i++)
        {
            // An unusable cached vector, stored before these checks existed, is embedded again rather than trusted.
            if (exampleCache.TryGet(texts[i], out var hit) && InvalidEmbeddingException.Problem(hit.Vector.Span) is null)
            {
                vectors[i] = hit.Vector;
            }
            else
            {
                missingText.Add(texts[i]);
                missingIndex.Add(i);
            }
        }

        if (missingText.Count > 0)
        {
            var fresh = await generator.GenerateAsync(missingText, cancellationToken: ct).ConfigureAwait(false);
            // A provider that batches, dedupes or drops inputs would otherwise pair vectors with
            // the wrong phrases and persist them under the wrong keys.
            CheckCount(fresh.Count, missingText.Count);

            for (var i = 0; i < missingIndex.Count; i++)
                vectors[missingIndex[i]] = fresh[i].Vector;

            // Checked against the cached hits too, before anything is stored.
            Validate(vectors);

            for (var i = 0; i < missingIndex.Count; i++)
                exampleCache.Set(missingText[i], fresh[i]);
        }
        else
        {
            Validate(vectors);
        }

        return vectors;
    }

    private static void CheckCount(int actual, int expected)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"Embedding generator returned {actual} vectors for {expected} inputs; results must correspond one-to-one and in order.");
        }
    }

    private static void Validate(ReadOnlyMemory<float>[] vectors)
    {
        var dimensions = vectors[0].Length;
        foreach (var vector in vectors)
        {
            if (InvalidEmbeddingException.Problem(vector.Span) is { } problem)
                throw new InvalidEmbeddingException(problem);
            if (vector.Length != dimensions)
                throw new InvalidEmbeddingException(InvalidEmbeddingException.DimensionMismatch);
        }
    }
}
