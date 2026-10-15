using AI.Sentinel.Audit;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>Collects every forwarded entry so a test can compare it with what the store holds.</summary>
public sealed class RecordingAuditForwarder : IAuditForwarder
{
    private readonly List<AuditEntry> _entries = new();

    public IReadOnlyList<AuditEntry> Entries
    {
        get { lock (_entries) { return _entries.ToArray(); } }
    }

    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        lock (_entries) { _entries.AddRange(batch); }
        return ValueTask.CompletedTask;
    }

    /// <summary>Waits for fire-and-forget delivery of <paramref name="count"/> entries, bounded by a timeout.</summary>
    public async Task WaitForAsync(int count, int timeoutMs = 5_000)
    {
        var deadline = Environment.TickCount + timeoutMs;
        while (Entries.Count < count && Environment.TickCount < deadline)
            await Task.Delay(25).ConfigureAwait(false);
    }

    /// <summary>Reads every entry of <paramref name="store"/> in append order.</summary>
    public static async Task<IReadOnlyList<AuditEntry>> ReadAllAsync(IAuditStore store)
    {
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), CancellationToken.None).ConfigureAwait(false))
            entries.Add(e);
        return entries;
    }
}
