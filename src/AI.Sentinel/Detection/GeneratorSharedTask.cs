using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>One lazily started task per embedding generator instance, shared by every caller with that generator.</summary>
/// <remarks>Keyed by generator instance, never by value: vectors from one generator must not be compared with
/// another's, and once nothing references a generator, the table releases its task.</remarks>
internal sealed class GeneratorSharedTask<T> where T : class
{
    private readonly ConditionalWeakTable<IEmbeddingGenerator<string, Embedding<float>>, Slot> _slots = new();

    private sealed class Slot
    {
#if NET9_0_OR_GREATER
        public readonly System.Threading.Lock Lock = new();
#else
        public readonly object Lock = new();
#endif
        public Task<T>? Task;
    }

    /// <summary>The value for <paramref name="generator"/>, produced by <paramref name="factory"/> on first use and
    /// shared by every later and concurrent caller with the same generator instance.</summary>
    /// <remarks>The first caller starts <paramref name="factory"/> on its own token and the others await that task.
    /// A task that fails or is cancelled is dropped, so the next call retries. A waiter whose own token is cancelled
    /// stops waiting without touching the shared task. If the shared task was cancelled by its owner's token,
    /// this caller retries for as long as its own token is live: it joins the next shared task or owns one on
    /// its own token, which only that token can cancel. An <see cref="OperationCanceledException"/> while the
    /// owner's token is live, such as an HttpClient timeout, is a fault: every waiter gets it and none retries.</remarks>
    public async Task<T> GetAsync(
        IEmbeddingGenerator<string, Embedding<float>> generator, Func<CancellationToken, Task<T>> factory, CancellationToken ct)
    {
        var slot = _slots.GetValue(generator, static _ => new Slot());
        while (true)
        {
            Task<T> task;
            TaskCompletionSource<T>? owned = null;
            lock (slot.Lock)
            {
                // A task that failed while every caller had already stopped waiting was never evicted by one.
                if (slot.Task is { IsCompleted: true, IsCompletedSuccessfully: false }) slot.Task = null;
                if (slot.Task is null)
                {
                    owned = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
                    slot.Task = owned.Task;
                }
                task = slot.Task;
            }

            // Started outside the lock: the example cache lookups and a generator's synchronous prefix run here.
            if (owned is not null) _ = RunAsync(owned, factory, ct);

            try
            {
                return await task.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (Exception) when (task.IsCompleted && !task.IsCompletedSuccessfully)
            {
                lock (slot.Lock)
                {
                    if (ReferenceEquals(slot.Task, task)) slot.Task = null;
                }

                if (!task.IsCanceled || ct.IsCancellationRequested) throw;
            }
        }
    }

    /// <summary>The shared task currently held for <paramref name="generator"/>. For tests.</summary>
    public bool TryPeek(IEmbeddingGenerator<string, Embedding<float>> generator, [NotNullWhen(true)] out Task<T>? task)
    {
        task = _slots.TryGetValue(generator, out var slot) ? slot.Task : null;
        return task is not null;
    }

    private static async Task RunAsync(TaskCompletionSource<T> target, Func<CancellationToken, Task<T>> factory, CancellationToken ct)
    {
        try
        {
            target.TrySetResult(await factory(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException ex) when (ct.IsCancellationRequested)
        {
            target.TrySetCanceled(ex.CancellationToken);
        }
        catch (Exception ex)
        {
            target.TrySetException(ex);
        }
    }
}
