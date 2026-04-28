using AI.Sentinel.Detectors.Sdk;
using Xunit;

namespace AI.Sentinel.Detectors.Sdk.Tests;

public class FakeEmbeddingGeneratorTests
{
    [Fact]
    public async Task IdenticalStrings_YieldCosineNearOne()
    {
        var gen = new FakeEmbeddingGenerator();
        var r1 = await gen.GenerateAsync(["the quick brown fox"]);
        var r2 = await gen.GenerateAsync(["the quick brown fox"]);
        var cosine = Cosine(r1[0].Vector.Span, r2[0].Vector.Span);

        Assert.True(cosine > 0.999f, $"Expected cosine >= 0.999, got {cosine}");
    }

    [Fact]
    public async Task UnrelatedStrings_YieldLowSimilarity()
    {
        var gen = new FakeEmbeddingGenerator();
        var r1 = await gen.GenerateAsync(["the quick brown fox"]);
        var r2 = await gen.GenerateAsync(["completely different unrelated text 12345"]);
        var cosine = Cosine(r1[0].Vector.Span, r2[0].Vector.Span);

        Assert.True(cosine < 0.5f, $"Expected cosine < 0.5 (low similarity), got {cosine}");
    }

    [Fact]
    public async Task NonEmptyString_YieldsL2NormalizedVector()
    {
        var gen = new FakeEmbeddingGenerator();
        var result = await gen.GenerateAsync(["the quick brown fox"]);
        var vec = result[0].Vector.ToArray();

        var sumSq = 0f;
        foreach (var x in vec)
        {
            sumSq += x * x;
        }

        Assert.Equal(1.0f, MathF.Sqrt(sumSq), precision: 5);
    }

    [Fact]
    public async Task EmptyString_YieldsAllZeroVector()
    {
        var gen = new FakeEmbeddingGenerator();
        var result = await gen.GenerateAsync([""]);
        var vec = result[0].Vector.ToArray();

        Assert.Equal(256, vec.Length);
        Assert.All(vec, x => Assert.Equal(0f, x));
    }

    private static float Cosine(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        float dot = 0f, na = 0f, nb = 0f;
        for (var i = 0; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            na += a[i] * a[i];
            nb += b[i] * b[i];
        }
        return dot / (MathF.Sqrt(na) * MathF.Sqrt(nb));
    }
}
