namespace AI.Sentinel.Sqlite.Local;

/// <summary>Thread-safe list of human-readable audit problems, shared by the session and the
/// store and forwarders it owns. Appends and forwarder errors can arrive on any thread.</summary>
internal sealed class LocalAuditProblems
{
    private readonly List<string> _problems = [];
#if NET9_0_OR_GREATER
    private readonly Lock _lock = new();
#else
    private readonly object _lock = new();
#endif

    public void Add(string problem)
    {
        lock (_lock)
        {
            _problems.Add(problem);
        }
    }

    public IReadOnlyList<string> Snapshot()
    {
        lock (_lock)
        {
            return [.. _problems];
        }
    }
}
