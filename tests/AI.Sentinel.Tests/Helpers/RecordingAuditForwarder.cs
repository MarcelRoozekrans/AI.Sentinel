using AI.Sentinel.Audit;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// Collects every forwarded batch so a test can compare it with what the store holds. Thread-safe:
/// forwarders run on fire-and-forget tasks and background readers, so every read returns a snapshot
/// taken under the same lock the writer uses, and waiting is signalled rather than polled.
/// </summary>
public sealed class RecordingAuditForwarder : IAuditForwarder
{
    /// <summary>How long a wait may take before the test fails. A hang detector, not a timing assumption:
    /// a passing run signals in milliseconds, and a loaded CI machine must never come near it.</summary>
    public static readonly TimeSpan DefaultWaitTimeout = TimeSpan.FromSeconds(30);

    private readonly List<IReadOnlyList<AuditEntry>> _batches = new();
    private readonly List<(int Count, TaskCompletionSource Signal)> _waiters = new();
    private int _entryCount;

    /// <summary>A snapshot of the batches received so far, in arrival order.</summary>
    public IReadOnlyList<IReadOnlyList<AuditEntry>> Batches
    {
        get { lock (_batches) { return _batches.ToArray(); } }
    }

    /// <summary>A snapshot of every entry received so far, in arrival order.</summary>
    public IReadOnlyList<AuditEntry> Entries
    {
        get { lock (_batches) { return _batches.SelectMany(b => b).ToArray(); } }
    }

    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        // Copy the batch: a caller may reuse or clear its list after SendAsync returns.
        var copy = batch.ToArray();
        List<TaskCompletionSource>? ready = null;
        lock (_batches)
        {
            _batches.Add(copy);
            _entryCount += copy.Length;
            for (var i = _waiters.Count - 1; i >= 0; i--)
            {
                if (_waiters[i].Count <= _entryCount)
                {
                    (ready ??= new()).Add(_waiters[i].Signal);
                    _waiters.RemoveAt(i);
                }
            }
        }
        if (ready is not null)
        {
            foreach (var signal in ready) signal.TrySetResult();
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>Completes once at least <paramref name="count"/> entries have arrived; throws
    /// <see cref="TimeoutException"/> if they have not arrived within <paramref name="timeout"/>.</summary>
    public Task WaitForAsync(int count, TimeSpan? timeout = null)
    {
        TaskCompletionSource signal;
        lock (_batches)
        {
            if (_entryCount >= count) return Task.CompletedTask;
            signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _waiters.Add((count, signal));
        }
        return WaitAsync(signal.Task, count, timeout ?? DefaultWaitTimeout);
    }

    private async Task WaitAsync(Task signal, int count, TimeSpan timeout)
    {
        try
        {
            await signal.WaitAsync(timeout).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            lock (_batches)
            {
                throw new TimeoutException($"Expected {count} forwarded entries within {timeout}, got {_entryCount}.", ex);
            }
        }
    }

    /// <summary>Reads every entry of <paramref name="store"/> in append order.</summary>
    public static async Task<IReadOnlyList<AuditEntry>> ReadAllAsync(IAuditStore store)
    {
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, CancellationToken.None).ConfigureAwait(false))
            entries.Add(e);
        return entries;
    }
}
