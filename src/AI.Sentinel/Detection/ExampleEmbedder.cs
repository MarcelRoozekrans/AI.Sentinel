using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Embeds reference phrases, using an optional persistent cache for the ones it already holds.</summary>
internal static class ExampleEmbedder
{
    public static async Task<ReadOnlyMemory<float>[]> EmbedAsync(
        IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, string[] texts, CancellationToken ct)
    {
        if (texts.Length == 0) return [];

        if (exampleCache is null)
        {
            var direct = await generator.GenerateAsync(texts, cancellationToken: ct).ConfigureAwait(false);
            return [.. direct.Select(e => e.Vector)];
        }

        // Embed only what the cache is missing. A warm persistent cache turns this whole method into
        // lookups, which is what makes semantic detection affordable in a per-invocation host.
        var vectors = new ReadOnlyMemory<float>[texts.Length];
        var missingText = new List<string>();
        var missingIndex = new List<int>();

        for (var i = 0; i < texts.Length; i++)
        {
            if (exampleCache.TryGet(texts[i], out var hit))
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
}
