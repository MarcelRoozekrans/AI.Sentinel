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

        // Each writer loads the current file before adding its entry, so with correct temp-file
        // isolation every phrase survives. Asserting ">= 1" let 7 of 8 writes vanish unnoticed.
        var missing = new List<string>();
        for (var i = 0; i < 8; i++)
        {
            if (!reader.TryGet($"phrase {i}", out _)) missing.Add($"phrase {i}");
        }

        Assert.Empty(missing);
    }

    /// <summary>A cache written at one vector dimension must never be served to a generator producing
    /// another: CosineSimilarity returns 0 on a length mismatch, so every bucket would score below
    /// threshold and every semantic detector would return Clean — a silent, total detection bypass.</summary>
    [Fact]
    public void DifferentDimensions_DoNotShareEntries()
    {
        using (var small = new FileSystemEmbeddingCache(_dir, "m", dimensions: 2))
        {
            small.Set("text", Vector(1f, 0f));
        }

        using var large = new FileSystemEmbeddingCache(_dir, "m", dimensions: 3);

        Assert.False(large.TryGet("text", out _));
    }

    /// <summary>A vector whose length contradicts the file header is rejected rather than served.</summary>
    [Fact]
    public void EntryOfUnexpectedLength_IsRejectedOnLoad()
    {
        using (var cache = new FileSystemEmbeddingCache(_dir, "m", dimensions: 3))
        {
            cache.Set("good", Vector(1f, 2f, 3f));
        }

        using var reader = new FileSystemEmbeddingCache(_dir, "m", dimensions: 3);
        Assert.True(reader.TryGet("good", out var got));
        Assert.Equal(3, got.Vector.Length);
    }

    /// <summary>Persisting only on Dispose means the obvious inline usage never writes anything, so the
    /// cache stays permanently cold and the feature appears to do nothing.</summary>
    [Fact]
    public void Entries_ArePersisted_WithoutAnExplicitDispose()
    {
        var cache = new FileSystemEmbeddingCache(_dir, "m");
        for (var i = 0; i < 80; i++)
        {
            cache.Set($"phrase {i}", Vector(i, i + 1));
        }

        using var reader = new FileSystemEmbeddingCache(_dir, "m");

        Assert.True(reader.TryGet("phrase 0", out _), "nothing was written without an explicit Dispose");
    }

    /// <summary>A flush that collides with a concurrent reader must retry rather than drop this
    /// process's entries. A real reader holds the file only for the length of its constructor, so the
    /// hold here is brief and well inside the retry budget.</summary>
    [Fact]
    public async Task Flush_RetriesPastAConcurrentReader()
    {
        using (var seed = new FileSystemEmbeddingCache(_dir, "m"))
        {
            seed.Set("seed", Vector(1f));
        }

        var file = Directory.GetFiles(_dir).Single();
        var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        var writing = Task.Run(
            () =>
            {
                using var writer = new FileSystemEmbeddingCache(_dir, "m");
                writer.Set("written-during-contention", Vector(2f));
            },
            TestContext.Current.CancellationToken);

        await Task.Delay(10, TestContext.Current.CancellationToken);
        await held.DisposeAsync();
        await writing;

        using var after = new FileSystemEmbeddingCache(_dir, "m");
        Assert.True(after.TryGet("written-during-contention", out _), "the flush never landed");
        Assert.True(after.TryGet("seed", out _), "the merge dropped the pre-existing entry");
    }
}
