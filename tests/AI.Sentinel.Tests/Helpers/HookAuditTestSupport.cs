using Xunit;
using AI.Sentinel.Audit;
using AI.Sentinel.Sqlite;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>Keeps hook CLI tests off the developer's real audit database and reads recorded ones back.</summary>
internal static class HookAuditTestSupport
{
    public const string SqliteVar = "SENTINEL_HOOK_AUDIT_SQLITE";
    public const string NdjsonVar = "SENTINEL_HOOK_AUDIT_NDJSON";

    public static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinel-hook-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void DeleteDir(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }

    public static async Task<(IReadOnlyList<AuditEntry> Entries, bool ChainValid)> ReadAsync(string databasePath)
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = databasePath });
        var ct = TestContext.Current.CancellationToken;
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), ct))
            entries.Add(e);
        var verification = await AuditHashChain.VerifyAsync(store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), ct), ct);
        return (entries, verification.IsIntact);
    }
}
