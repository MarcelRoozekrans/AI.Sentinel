using System.Diagnostics;

namespace AI.Sentinel.Sqlite.Local;

/// <summary>Thread-safe set of human-readable audit problems, shared by the session and the
/// store and forwarders it owns. Appends and forwarder errors can arrive on any thread.
/// Each distinct message is stored once, so a failure that repeats on every append (a full disk)
/// cannot grow the list, and the optional callback fires only on a message's first occurrence.</summary>
internal sealed class LocalAuditProblems(Action<string>? onProblem = null)
{
    private readonly List<string> _problems = [];
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
#if NET9_0_OR_GREATER
    private readonly Lock _lock = new();
#else
    private readonly object _lock = new();
#endif

    public void Add(string problem)
    {
        lock (_lock)
        {
            if (!_seen.Add(problem)) return;
            _problems.Add(problem);
        }

        // Outside the lock: the callback may write to a slow stream.
        InvokeCallback(problem);
    }

    public IReadOnlyList<string> Snapshot()
    {
        lock (_lock)
        {
            return [.. _problems];
        }
    }

    private void InvokeCallback(string problem)
    {
        if (onProblem is null) return;

        try
        {
            onProblem(problem);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            Debug.WriteLine($"Audit problem report failed: {ex.Message}");
        }
    }
}
