namespace AI.Sentinel.Audit;

/// <summary>
/// Reads a session's recent audit entries from an <see cref="IAuditStore"/>. The query is a hint:
/// a custom store may ignore any filter, so every entry is re-checked here.
/// </summary>
internal static class SessionHistory
{
    /// <summary>The most entries <see cref="ReadAsync"/> returns.</summary>
    internal const int MaxEntries = 50;

    /// <summary>Entries older than this, relative to the scan time, are not history.</summary>
    internal static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);

    /// <summary>The number of earlier hits at which a detector's finding escalates.</summary>
    internal const int EscalationThreshold = 2;

    /// <summary>
    /// Returns the newest <see cref="MaxEntries"/> entries of <paramref name="sessionId"/> from the last
    /// <see cref="MaxAge"/>, oldest first. A store failure is reported through <paramref name="onFailure"/>
    /// and yields an empty list; cancellation is rethrown.
    /// </summary>
    internal static async ValueTask<IReadOnlyList<AuditEntry>> ReadAsync(
        IAuditStore store, string sessionId, DateTimeOffset now, Action<string>? onFailure, CancellationToken ct)
    {
        var from = now - MaxAge;
        try
        {
            var query = new AuditQuery { SessionId = sessionId, Reverse = true, PageSize = MaxEntries, From = from };
            var matches = new List<AuditEntry>();
            await foreach (var entry in store.QueryAsync(query, ct).WithCancellation(ct).ConfigureAwait(false))
            {
                if (string.Equals(entry.SessionId, sessionId, StringComparison.Ordinal) && entry.Timestamp >= from)
                    matches.Add(entry);
            }

            // The store may ignore Reverse, so order and trim here.
            matches.Sort(static (a, b) => b.Timestamp.CompareTo(a.Timestamp));
            if (matches.Count > MaxEntries) matches.RemoveRange(MaxEntries, matches.Count - MaxEntries);
            matches.Reverse();
            return matches;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            Report(onFailure, sessionId, ex);
            return [];
        }
    }

    /// <summary>
    /// Counts the entries of <paramref name="sessionId"/> from <paramref name="detectorId"/> with a severity
    /// above <see cref="Detection.Severity.None"/>, at most <see cref="EscalationThreshold"/>. A store failure is
    /// reported through <paramref name="onFailure"/> and yields 0; cancellation is rethrown.
    /// </summary>
    internal static async ValueTask<int> CountEarlierHitsAsync(
        IAuditStore store, string sessionId, string detectorId, DateTimeOffset now, Action<string>? onFailure,
        CancellationToken ct)
    {
        var from = now - MaxAge;
        try
        {
            var query = new AuditQuery
            {
                SessionId = sessionId, DetectorId = detectorId, Reverse = true, PageSize = EscalationThreshold, From = from,
            };
            var count = 0;
            await foreach (var entry in store.QueryAsync(query, ct).WithCancellation(ct).ConfigureAwait(false))
            {
                if (string.Equals(entry.SessionId, sessionId, StringComparison.Ordinal)
                    && string.Equals(entry.DetectorId, detectorId, StringComparison.Ordinal)
                    && entry.Timestamp >= from
                    && entry.Severity > Detection.Severity.None
                    && ++count >= EscalationThreshold)
                    break;
            }
            return count;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            Report(onFailure, sessionId, ex);
            return 0;
        }
    }

    private static void Report(Action<string>? onFailure, string sessionId, Exception ex) =>
        onFailure?.Invoke(
            $"AI.Sentinel: the audit history of session {sessionId} could not be read ({ex.GetType().Name}: {ex.Message}); this scan runs without it.");
}
