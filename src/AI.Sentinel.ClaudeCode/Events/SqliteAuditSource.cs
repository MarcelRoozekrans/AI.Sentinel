using AI.Sentinel.Audit;
using AI.Sentinel.Sqlite;
using Microsoft.Data.Sqlite;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>Reads the audit file the hooks write, read-only, so it never changes it. A file that does not exist yet, or is older than
/// the schema that routes entries, cannot be read now, and is reported as such rather than as an empty audit.</summary>
internal sealed class SqliteAuditSource(string databasePath) : IAuditSource
{
    public async Task<AuditPage> ReadAfterAsync(long after, int limit, CancellationToken ct)
    {
        if (!File.Exists(databasePath))
        {
            return AuditPage.Unreadable;
        }

        try
        {
            var store = SqliteAuditStore.OpenReadOnly(databasePath);
            await using var _ = store.ConfigureAwait(false);
            var page = await store.ReadAfterAsync(after, limit, ct).ConfigureAwait(false);
            return new AuditPage(page.Rows, page.FirstSequence, page.LastSequence);
        }
        catch (Exception e) when (e is SqliteException or InvalidOperationException)
        {
            // Busy, being written by an upgrade, or not yet current: the next cycle reads it. It is not an empty audit, so the cursor stays.
            return AuditPage.Unreadable;
        }
    }
}
