using System.Diagnostics;
using AI.Sentinel.Audit;

namespace AI.Sentinel.Sqlite.Local;

/// <summary>
/// The audit store and forwarders one CLI process writes through, built by <see cref="LocalAudit.Open"/>.
/// Register <see cref="Store"/> as <see cref="IAuditStore"/> and <see cref="Forwarders"/> as
/// <see cref="IAuditForwarder"/>, and call <see cref="FlushAsync"/> before the process exits.
/// </summary>
internal sealed class LocalAuditSession : IAsyncDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(10);

    private readonly IAuditStore _innerStore;
    private readonly SourceTaggingAuditStore _store;
    private readonly TrackingAuditForwarder[] _forwarders;
    private readonly LocalAuditProblems _problems;

    /// <param name="innerStore">The store entries are appended to. The session owns and disposes it.</param>
    /// <param name="source">The <see cref="AuditEntry.Source"/> stamped on every entry.</param>
    /// <param name="forwarders">Forwarders to track. The session owns and disposes them.</param>
    /// <param name="problems">Where problems go, including any already found while opening.</param>
    internal LocalAuditSession(
        IAuditStore innerStore,
        string source,
        IEnumerable<IAuditForwarder> forwarders,
        LocalAuditProblems problems)
    {
        _innerStore = innerStore;
        _problems = problems;
        _store = new SourceTaggingAuditStore(innerStore, source, problems.Add);
        _forwarders = [.. forwarders.Select(f => new TrackingAuditForwarder(f))];
    }

    /// <summary>The store to register. It tags each entry's source and never throws on append.</summary>
    public IAuditStore Store => _store;

    /// <summary>The forwarders to register, each counting the entries it has sent.</summary>
    public IReadOnlyList<IAuditForwarder> Forwarders => _forwarders;

    /// <summary>Human-readable problems found so far, one per problem, for the CLI to report.</summary>
    public IReadOnlyList<string> Problems => _problems.Snapshot();

    /// <summary>
    /// Waits until every forwarder has sent as many entries as <see cref="Store"/> has seen appends,
    /// or until <paramref name="timeout"/> passes. Counting sends rather than tracking in-flight tasks
    /// matters: <see cref="AuditForwarding"/> starts each send on <see cref="Task.Run(Func{Task})"/>,
    /// so a send may not have reached its forwarder yet when the flush begins.
    /// </summary>
    public async Task FlushAsync(TimeSpan timeout)
    {
        var target = _store.AppendCount;
        var elapsed = Stopwatch.StartNew();
        while (!AllSent(target) && elapsed.Elapsed < timeout)
        {
            await Task.Delay(PollInterval).ConfigureAwait(false);
        }
    }

    /// <summary>Disposes the forwarders, then the store. Never throws: a failing dispose is recorded
    /// in <see cref="Problems"/> and the rest are still disposed, so it cannot change a CLI's exit.</summary>
    public async ValueTask DisposeAsync()
    {
        foreach (var forwarder in _forwarders)
        {
            await DisposeSafelyAsync(forwarder, "an audit forwarder").ConfigureAwait(false);
        }

        await DisposeSafelyAsync(_innerStore, "the audit store").ConfigureAwait(false);
    }

    private bool AllSent(long target)
    {
        foreach (var forwarder in _forwarders)
        {
            if (forwarder.EntriesSent < target) return false;
        }
        return true;
    }

    private async ValueTask DisposeSafelyAsync(object owned, string what)
    {
        try
        {
            switch (owned)
            {
                case IAsyncDisposable asyncDisposable:
                    await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                    break;
                case IDisposable disposable:
                    disposable.Dispose();
                    break;
            }
        }
#pragma warning disable CA1031 // Shutdown must not fail because an audit component did.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _problems.Add($"Could not close {what}: {ex.GetType().Name}: {ex.Message}");
        }
    }
}
