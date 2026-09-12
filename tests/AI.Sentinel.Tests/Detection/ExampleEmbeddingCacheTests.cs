using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Tests.Helpers;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>SemanticDetectorBase embeds its example phrases on first scan and never consults the
/// cache while doing so. In a long-lived host that is a one-time startup cost; in the hook CLIs,
/// which run one process per prompt and per tool call, it is 82 round-trips embedding 332 phrases
/// on every invocation. These pin the cache seam that makes a persistent cache possible.</summary>
public class ExampleEmbeddingCacheTests
{
    private static SentinelContext Context() => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, "some unremarkable text") },
        new List<AuditEntry>());

    private sealed class CountingGenerator : IEmbeddingGenerator<string, Embedding<float>>
    {
        private readonly FakeEmbeddingGenerator _inner = new();
        public List<string> Embedded { get; } = [];

        public EmbeddingGeneratorMetadata Metadata => _inner.Metadata;

        public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken ct = default)
        {
            var list = values.ToList();
            Embedded.AddRange(list);
            return await _inner.GenerateAsync(list, options, ct);
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }

    private sealed class ProbeDetector(SentinelOptions options) : SemanticDetectorBase(options)
    {
        public static readonly string[] Phrases = ["first probe phrase", "second probe phrase"];
        public override DetectorId Id => new("TST-01");
        public override DetectorCategory Category => DetectorCategory.Security;
        protected override string[] HighExamples => Phrases;
        protected override string[] MediumExamples => [];
        protected override string[] LowExamples => [];
    }

    [Fact]
    public async Task ExampleEmbeddings_AreServedFromTheExampleCache_WhenAlreadyPresent()
    {
        var generator = new CountingGenerator();
        var cache = new InMemoryLruEmbeddingCache();

        // Pre-populate exactly as a warm persistent cache would be.
        var warm = await new FakeEmbeddingGenerator().GenerateAsync(ProbeDetector.Phrases, null, TestContext.Current.CancellationToken);
        for (var i = 0; i < ProbeDetector.Phrases.Length; i++)
        {
            cache.Set(ProbeDetector.Phrases[i], warm[i]);
        }

        var options = new SentinelOptions { EmbeddingGenerator = generator, ExampleEmbeddingCache = cache };
        await new ProbeDetector(options).AnalyzeAsync(Context(), TestContext.Current.CancellationToken);

        foreach (var phrase in ProbeDetector.Phrases)
        {
            Assert.DoesNotContain(phrase, generator.Embedded, StringComparer.Ordinal);
        }
    }

    [Fact]
    public async Task ExampleEmbeddings_ArePutIntoTheExampleCache_OnFirstScan()
    {
        var generator = new CountingGenerator();
        var cache = new InMemoryLruEmbeddingCache();
        var options = new SentinelOptions { EmbeddingGenerator = generator, ExampleEmbeddingCache = cache };

        await new ProbeDetector(options).AnalyzeAsync(Context(), TestContext.Current.CancellationToken);

        foreach (var phrase in ProbeDetector.Phrases)
        {
            Assert.True(cache.TryGet(phrase, out _), $"'{phrase}' was not written to the example cache");
        }
    }

    /// <summary>The scan-time input must never reach the example cache: in the hook CLIs that text is
    /// the user's prompt, and the example cache is the one that gets persisted to disk.</summary>
    [Fact]
    public async Task ScanInput_IsNeverWrittenToTheExampleCache()
    {
        const string prompt = "a distinctive user prompt that must not be persisted";
        var cache = new InMemoryLruEmbeddingCache();
        var options = new SentinelOptions
        {
            EmbeddingGenerator = new FakeEmbeddingGenerator(),
            ExampleEmbeddingCache = cache,
        };

        var ctx = new SentinelContext(
            new AgentId("a"), new AgentId("b"), SessionId.New(),
            new List<ChatMessage> { new(ChatRole.User, prompt) },
            new List<AuditEntry>());

        await new ProbeDetector(options).AnalyzeAsync(ctx, TestContext.Current.CancellationToken);

        Assert.False(cache.TryGet(prompt, out _), "the user's prompt reached the persistable example cache");
    }

    /// <summary>The whole point: a second process with a warm file embeds no example phrases at all.
    /// Two cache instances over one directory stand in for two hook invocations.</summary>
    [Fact]
    public async Task SecondProcess_WithAWarmFileCache_EmbedsNoExamplePhrases()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ai-sentinel-warm-" + Guid.NewGuid().ToString("N"));
        try
        {
            var first = new CountingGenerator();
            using (var cache = new FileSystemEmbeddingCache(dir, "test-model"))
            {
                var options = new SentinelOptions { EmbeddingGenerator = first, ExampleEmbeddingCache = cache };
                await new ProbeDetector(options).AnalyzeAsync(Context(), TestContext.Current.CancellationToken);
            }

            foreach (var phrase in ProbeDetector.Phrases)
            {
                Assert.Contains(phrase, first.Embedded, StringComparer.Ordinal);
            }

            var second = new CountingGenerator();
            using (var cache = new FileSystemEmbeddingCache(dir, "test-model"))
            {
                var options = new SentinelOptions { EmbeddingGenerator = second, ExampleEmbeddingCache = cache };
                await new ProbeDetector(options).AnalyzeAsync(Context(), TestContext.Current.CancellationToken);
            }

            foreach (var phrase in ProbeDetector.Phrases)
            {
                Assert.DoesNotContain(phrase, second.Embedded, StringComparer.Ordinal);
            }

            // Exactly one call remains, for the scan input.
            Assert.Single(second.Embedded);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}
