using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>The example phrases are embedded once per generator and shared by every concurrent scan:
/// the first use runs as one task that the others await, and a failed or cancelled task is not kept.</summary>
public class ExampleVectorStoreTests
{
    private static readonly string[] High = ["high one", "high two", "high three"];
    private static readonly string[] Medium = ["medium one", "medium two"];
    private static readonly string[] Low = ["low one"];

    private sealed class StoreDetector(SentinelOptions options) : SemanticDetectorBase(options)
    {
        protected override string ReviewCriterion => "A test-only detector with a generic criterion, never reviewed by a real judge.";
        public override DetectorId Id => new("TST-02");
        public override DetectorCategory Category => DetectorCategory.Security;
        protected override string[] HighExamples => High;
        protected override string[] MediumExamples => Medium;
        protected override string[] LowExamples => Low;
    }

    private static StoreDetector Detector() => new(new SentinelOptions());

    [Fact]
    public async Task Concurrent_first_uses_embed_examples_once_per_generator()
    {
        var ct = TestContext.Current.CancellationToken;
        var gen = new YieldingEmbeddingGenerator { Gate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var detector = Detector();

        var tasks = Enumerable.Range(0, 20).Select(_ => detector.GetExampleVectorsAsync(gen, null, ct)).ToList();
        gen.Gate.SetResult();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(3, gen.Calls);
        Assert.All(results, r => Assert.Same(results[0], r));
        Assert.Equal(3, results[0].High.Length);
        Assert.Equal(2, results[0].Medium.Length);
        Assert.Single(results[0].Low);
    }

    [Fact]
    public async Task Two_generators_get_their_own_vectors()
    {
        var ct = TestContext.Current.CancellationToken;
        var genA = new YieldingEmbeddingGenerator();
        var genB = new YieldingEmbeddingGenerator();
        var detector = Detector();

        var a = await detector.GetExampleVectorsAsync(genA, null, ct);
        var b = await detector.GetExampleVectorsAsync(genB, null, ct);

        Assert.Equal(3, genA.Calls);
        Assert.Equal(3, genB.Calls);
        Assert.NotSame(a, b);
    }

    [Fact]
    public async Task Failed_first_use_is_retried_on_next_call()
    {
        var ct = TestContext.Current.CancellationToken;
        var first = true;
        var gen = new YieldingEmbeddingGenerator(_ =>
        {
            var fail = first;
            first = false;
            return fail;
        });
        var detector = Detector();

        await Assert.ThrowsAsync<HttpRequestException>(() => detector.GetExampleVectorsAsync(gen, null, ct));
        var callsAfterFailure = gen.Calls;

        var vectors = await detector.GetExampleVectorsAsync(gen, null, ct);

        Assert.Equal(1, callsAfterFailure);
        Assert.Equal(3, vectors.High.Length);
        Assert.Equal(4, gen.Calls);
    }

    [Fact]
    public async Task Task_that_faults_after_all_callers_left_is_not_kept()
    {
        var ct = TestContext.Current.CancellationToken;
        var failing = true;
        var gen = new YieldingEmbeddingGenerator(_ => failing)
        {
            Gate = new(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        var detector = Detector();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var caller1 = detector.GetExampleVectorsAsync(gen, null, cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => caller1);

        Assert.True(detector.TryPeekExampleTask(gen, out var shared));
        gen.Gate.SetResult();
        _ = await Task.WhenAny(shared);
        Assert.True(shared.IsFaulted);
        failing = false;
        gen.Gate = null;

        var vectors = await detector.GetExampleVectorsAsync(gen, null, ct);
        Assert.Equal(3, vectors.High.Length);
    }

    [Fact]
    public async Task Cancelled_first_caller_does_not_fail_other_waiters()
    {
        var ct = TestContext.Current.CancellationToken;
        var gen = new YieldingEmbeddingGenerator { Gate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var detector = Detector();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var caller1 = detector.GetExampleVectorsAsync(gen, null, cts.Token);
        var caller2 = detector.GetExampleVectorsAsync(gen, null, CancellationToken.None);
        cts.Cancel();
        gen.Gate.SetResult();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => caller1);
        var vectors = await caller2;
        Assert.Equal(3, vectors.High.Length);
    }

    [Fact]
    public async Task Waiter_with_cancelled_token_propagates()
    {
        var ct = TestContext.Current.CancellationToken;
        var gen = new YieldingEmbeddingGenerator { Gate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var detector = Detector();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var caller1 = detector.GetExampleVectorsAsync(gen, null, ct);
        var caller2 = detector.GetExampleVectorsAsync(gen, null, cts.Token);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => caller2);

        gen.Gate.SetResult();
        Assert.Equal(3, (await caller1).High.Length);
        Assert.Equal(3, gen.Calls);
    }

    [Fact]
    public async Task Owner_timeout_on_a_live_token_faults_the_shared_task()
    {
        // HttpClient reports its timeout as a TaskCanceledException while the caller's token is not cancelled.
        var ct = TestContext.Current.CancellationToken;
        var gen = new YieldingEmbeddingGenerator(_ => true)
        {
            Gate = new(TaskCreationOptions.RunContinuationsAsynchronously),
            Failure = _ => new TaskCanceledException("timed out"),
        };
        var detector = Detector();

        var owner = detector.GetExampleVectorsAsync(gen, null, ct);
        var waiter = detector.GetExampleVectorsAsync(gen, null, ct);
        Assert.True(detector.TryPeekExampleTask(gen, out var shared));
        gen.Gate.SetResult();

        await Assert.ThrowsAsync<TaskCanceledException>(() => owner);
        await Assert.ThrowsAsync<TaskCanceledException>(() => waiter);
        // A fault, not an owner cancellation, so the waiter does not start a second timeout of its own.
        Assert.True(shared.IsFaulted);
        Assert.Equal(1, gen.Calls);
        Assert.False(detector.TryPeekExampleTask(gen, out _));
    }

    [Fact]
    public async Task Waiter_outlives_successive_cancelled_owners()
    {
        // Each owner's task is cancelled by its own token. Which caller owns the retry task is a race,
        // so the scenario repeats until a second owner cancelled under the waiter.
        var ct = TestContext.Current.CancellationToken;
        var secondOwnerCancelled = 0;
        for (var round = 0; round < 50; round++)
        {
            using var first = CancellationTokenSource.CreateLinkedTokenSource(ct);
            using var second = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var gen = new OwnerCancellingGenerator(first, second);
            var detector = Detector();

            var owner1 = detector.GetExampleVectorsAsync(gen, null, first.Token);
            var waiter = round % 2 == 0 ? detector.GetExampleVectorsAsync(gen, null, ct) : null;
            var owner2 = detector.GetExampleVectorsAsync(gen, null, second.Token);
            waiter ??= detector.GetExampleVectorsAsync(gen, null, ct);
            gen.Gate.SetResult();

            Assert.Equal(3, (await waiter).High.Length);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner1);
            if (gen.SecondCancelled)
            {
                secondOwnerCancelled++;
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner2);
            }
        }

        Assert.True(secondOwnerCancelled > 0, "No round had a second cancelled owner under the waiter.");
    }

    /// <summary>Holds every call at <see cref="Gate"/>, then cancels the caller's token if it belongs to
    /// <c>first</c> or <c>second</c> and throws, so that caller's task ends cancelled by its owner.</summary>
    private sealed class OwnerCancellingGenerator(CancellationTokenSource first, CancellationTokenSource second)
        : IEmbeddingGenerator<string, Embedding<float>>
    {
        private readonly FakeEmbeddingGenerator _inner = new();
        private int _secondCancelled;

        public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool SecondCancelled => Volatile.Read(ref _secondCancelled) == 1;
        public EmbeddingGeneratorMetadata Metadata { get; } = new("owner-cancelling", null, null, 256);

        public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default)
        {
            var list = values.ToList();
            await Gate.Task.ConfigureAwait(false);
            if (cancellationToken == first.Token)
            {
                await first.CancelAsync();
            }
            else if (cancellationToken == second.Token)
            {
                Volatile.Write(ref _secondCancelled, 1);
                await second.CancelAsync();
            }
            cancellationToken.ThrowIfCancellationRequested();
            return await _inner.GenerateAsync(list, options, cancellationToken).ConfigureAwait(false);
        }

        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }

    [Fact]
    public async Task Example_cache_hits_skip_the_generator()
    {
        var ct = TestContext.Current.CancellationToken;
        var cache = new InMemoryLruEmbeddingCache();
        var all = High.Concat(Medium).Concat(Low).ToList();
        var warm = await new FakeEmbeddingGenerator().GenerateAsync(all, null, ct);
        for (var i = 0; i < all.Count; i++)
        {
            cache.Set(all[i], warm[i]);
        }
        var gen = new YieldingEmbeddingGenerator();

        var vectors = await Detector().GetExampleVectorsAsync(gen, cache, ct);

        Assert.Equal(0, gen.Calls);
        Assert.Equal(3, vectors.High.Length);
    }

    [Fact]
    public async Task Public_and_pipeline_paths_share_example_vectors_for_same_generator()
    {
        var ct = TestContext.Current.CancellationToken;
        var gen = new YieldingEmbeddingGenerator();
        var detector = new StoreDetector(new SentinelOptions { EmbeddingGenerator = gen });
        var ctx = new SentinelContext(
            new AgentId("a"), new AgentId("b"), SessionId.New(),
            new List<ChatMessage> { new(ChatRole.User, "some unremarkable text") },
            new List<AuditEntry>());

        await detector.AnalyzeAsync(ctx, ct);
        var callsAfterAnalyze = gen.Calls;
        foreach (var example in High.Concat(Medium).Concat(Low))
        {
            Assert.Contains(gen.Inputs, i => string.Equals(i, example, StringComparison.Ordinal));
        }

        await detector.GetExampleVectorsAsync(gen, null, ct);
        Assert.Equal(callsAfterAnalyze, gen.Calls);

        foreach (var example in High.Concat(Medium).Concat(Low))
        {
            Assert.Single(gen.Inputs, i => string.Equals(i, example, StringComparison.Ordinal));
        }
    }
}
