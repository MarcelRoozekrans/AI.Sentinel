namespace AI.Sentinel.Tests.Helpers;

/// <summary>A clock that moves only when a test calls <see cref="Advance"/>, so a timeout fires exactly when the test
/// says and not when a loaded machine gets round to it.</summary>
/// <remarks>Timers fire in due-time order, then in the order they were created, on the thread that calls
/// <see cref="Advance"/>. Only one-shot use is exercised: a periodic timer fires at most once per call.</remarks>
public sealed class ManualTimeProvider : TimeProvider
{
#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _lock = new();
#else
    private readonly object _lock = new();
#endif
    private readonly List<ManualTimer> _timers = [];
    private readonly List<(int Count, TaskCompletionSource Signal)> _waiters = [];
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private long _created;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_lock) return _now;
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        List<TaskCompletionSource> reached = [];
        lock (_lock)
        {
            timer.Order = _created++;
            _timers.Add(timer);
            timer.ChangeLocked(dueTime, period);
            for (var i = _waiters.Count - 1; i >= 0; i--)
            {
                if (_created < _waiters[i].Count) continue;
                reached.Add(_waiters[i].Signal);
                _waiters.RemoveAt(i);
            }
        }

        foreach (var signal in reached) signal.TrySetResult();
        return timer;
    }

    /// <summary>Completes once <paramref name="count"/> timers have been created in all, so a test advances the clock
    /// only after the code under test has started its timeouts.</summary>
    public Task TimersCreated(int count)
    {
        lock (_lock)
        {
            if (_created >= count) return Task.CompletedTask;
            var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _waiters.Add((count, signal));
            return signal.Task;
        }
    }

    /// <summary>Moves the clock forward by <paramref name="by"/> and fires every timer that is due.</summary>
    public void Advance(TimeSpan by)
    {
        List<ManualTimer> due;
        lock (_lock)
        {
            _now += by;
            due = [.. _timers.Where(t => t.Due is { } d && d <= _now).OrderBy(t => t.Due).ThenBy(t => t.Order)];
            foreach (var timer in due) timer.Due = timer.Period > TimeSpan.Zero ? _now + timer.Period : null;
        }

        foreach (var timer in due) timer.Fire();
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
    {
        public long Order { get; set; }
        public DateTimeOffset? Due { get; set; }
        public TimeSpan Period { get; private set; }
        private bool _disposed;

        public void ChangeLocked(TimeSpan dueTime, TimeSpan period)
        {
            Due = dueTime == Timeout.InfiniteTimeSpan ? null : owner._now + dueTime;
            Period = period == Timeout.InfiniteTimeSpan ? TimeSpan.Zero : period;
        }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (owner._lock)
            {
                if (_disposed) return false;
                ChangeLocked(dueTime, period);
                return true;
            }
        }

        public void Fire()
        {
            lock (owner._lock)
            {
                if (_disposed) return;
            }

            callback(state);
        }

        public void Dispose()
        {
            lock (owner._lock)
            {
                _disposed = true;
                Due = null;
                owner._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
