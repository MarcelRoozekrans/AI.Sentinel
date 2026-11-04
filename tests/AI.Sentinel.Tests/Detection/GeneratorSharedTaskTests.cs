using Xunit;
using AI.Sentinel.Detection;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.Detection;

public class GeneratorSharedTaskTests
{
    private sealed class Box;

    [Fact]
    public async Task ConcurrentCallers_ShareOneFactoryRun()
    {
        var shared = new GeneratorSharedTask<Box>();
        var generator = new FakeEmbeddingGenerator();
        var gate = new TaskCompletionSource<Box>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        Task<Box> Factory(CancellationToken _) { Interlocked.Increment(ref calls); return gate.Task; }

        var callers = Enumerable.Range(0, 10)
            .Select(_ => Task.Run(() => shared.GetAsync(generator, Factory, CancellationToken.None)))
            .ToArray();
        await Task.Delay(50, TestContext.Current.CancellationToken);
        var expected = new Box();
        gate.SetResult(expected);
        var results = await Task.WhenAll(callers);

        Assert.Equal(1, calls);
        Assert.All(results, r => Assert.Same(expected, r));
    }

    [Fact]
    public async Task FailedTask_IsDroppedAndRetried()
    {
        var shared = new GeneratorSharedTask<Box>();
        var generator = new FakeEmbeddingGenerator();
        var calls = 0;
        Task<Box> Factory(CancellationToken _)
        {
            return ++calls == 1 ? throw new InvalidOperationException("boom") : Task.FromResult(new Box());
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => shared.GetAsync(generator, Factory, CancellationToken.None));
        var second = await shared.GetAsync(generator, Factory, CancellationToken.None);

        Assert.NotNull(second);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task WaiterCancellation_DoesNotCancelSharedTask()
    {
        var shared = new GeneratorSharedTask<Box>();
        var generator = new FakeEmbeddingGenerator();
        var gate = new TaskCompletionSource<Box>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        Task<Box> Factory(CancellationToken _) { Interlocked.Increment(ref calls); return gate.Task; }

        var owner = shared.GetAsync(generator, Factory, CancellationToken.None);
        using var waiterCts = new CancellationTokenSource();
        var waiter = shared.GetAsync(generator, Factory, waiterCts.Token);
        await waiterCts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);

        Assert.True(shared.TryPeek(generator, out var task));
        Assert.False(task.IsCompleted);
        var expected = new Box();
        gate.SetResult(expected);
        Assert.Same(expected, await owner);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task OwnerCancellation_LiveWaiterRetries()
    {
        var shared = new GeneratorSharedTask<Box>();
        var generator = new FakeEmbeddingGenerator();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        async Task<Box> Factory(CancellationToken token)
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                started.SetResult();
                await Task.Delay(Timeout.Infinite, token);
            }
            return new Box();
        }

        using var ownerCts = new CancellationTokenSource();
        var owner = shared.GetAsync(generator, Factory, ownerCts.Token);
        await started.Task;
        var waiter = shared.GetAsync(generator, Factory, CancellationToken.None);
        await ownerCts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner);
        Assert.NotNull(await waiter);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task DifferentGenerators_GetSeparateTasks()
    {
        var shared = new GeneratorSharedTask<Box>();
        var calls = 0;
        Task<Box> Factory(CancellationToken _) { Interlocked.Increment(ref calls); return Task.FromResult(new Box()); }

        var a = await shared.GetAsync(new FakeEmbeddingGenerator(), Factory, CancellationToken.None);
        var b = await shared.GetAsync(new FakeEmbeddingGenerator(), Factory, CancellationToken.None);

        Assert.NotSame(a, b);
        Assert.Equal(2, calls);
    }
}
