using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>The cache that makes semantic detection affordable in a per-invocation host: without it
/// every hook process re-embeds all 332 example phrases over 82 round-trips.</summary>
public sealed class FileSystemEmbeddingCacheTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ai-sentinel-cache-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private static Embedding<float> Vector(params float[] values) => new(values);

    [Fact]
    public void Entries_SurviveAcrossInstances()
    {
        using (var writer = new FileSystemEmbeddingCache(_dir, "text-embedding-3-small"))
        {
            writer.Set("first probe phrase", Vector(0.1f, 0.2f, 0.3f));
        }

        using var reader = new FileSystemEmbeddingCache(_dir, "text-embedding-3-small");

        Assert.True(reader.TryGet("first probe phrase", out var got));
        Assert.Equal(new[] { 0.1f, 0.2f, 0.3f }, got.Vector.ToArray());
    }

    /// <summary>Vectors from one model are meaningless to another, and IEmbeddingCache keys on text
    /// alone — so the model has to separate them or a model switch silently returns stale vectors.</summary>
    [Fact]
    public void DifferentModels_DoNotShareEntries()
    {
        using (var a = new FileSystemEmbeddingCache(_dir, "text-embedding-3-small"))
        {
            a.Set("shared text", Vector(1f, 0f));
        }

        using var b = new FileSystemEmbeddingCache(_dir, "text-embedding-3-large");

        Assert.False(b.TryGet("shared text", out _));
    }

    [Fact]
    public void CorruptFile_IsTreatedAsEmpty_NotAFailure()
    {
        using (var seed = new FileSystemEmbeddingCache(_dir, "m"))
        {
            seed.Set("text", Vector(1f, 2f));
        }

        var file = Directory.GetFiles(_dir).Single();
        File.WriteAllText(file, "not a cache file at all");

        using var cache = new FileSystemEmbeddingCache(_dir, "m");

        Assert.False(cache.TryGet("text", out _));
        cache.Set("text", Vector(3f, 4f));   // must still be usable
        Assert.True(cache.TryGet("text", out _));
    }

    [Fact]
    public void TruncatedFile_IsTreatedAsEmpty()
    {
        using (var seed = new FileSystemEmbeddingCache(_dir, "m"))
        {
            seed.Set("text", Vector(1f, 2f, 3f, 4f));
        }

        var file = Directory.GetFiles(_dir).Single();
        var bytes = File.ReadAllBytes(file);
        File.WriteAllBytes(file, bytes[..(bytes.Length / 2)]);

        using var cache = new FileSystemEmbeddingCache(_dir, "m");

        Assert.False(cache.TryGet("text", out _));
    }

    [Fact]
    public void ConcurrentWriters_LeaveAReadableFile()
    {
        Parallel.For(0, 8, i =>
        {
            using var cache = new FileSystemEmbeddingCache(_dir, "m");
            cache.Set($"phrase {i}", Vector(i, i + 1));
        });

        using var reader = new FileSystemEmbeddingCache(_dir, "m");

        // Last writer wins, so not every phrase need survive — but the file must parse.
        var found = 0;
        for (var i = 0; i < 8; i++)
        {
            if (reader.TryGet($"phrase {i}", out _)) found++;
        }

        Assert.True(found >= 1, "no entry survived — the file did not parse");
    }
}
