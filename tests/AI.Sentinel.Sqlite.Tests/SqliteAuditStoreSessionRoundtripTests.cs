using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

/// <summary>
/// Round-trips <see cref="AuditEntry.SessionId"/> through SqliteAuditStore Append/Query so the
/// session-correlation column added in schema v3 actually persists and reads back. Pins both the
/// happy path (non-null session) and the back-compat path (null session for non-AUTHZ entries).
/// </summary>
public sealed class SqliteAuditStoreSessionRoundtripTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-sess-{Guid.NewGuid():N}.db"));

    public void Dispose()
    {
        TryDelete(_dbPath);
        TryDelete(_dbPath + "-wal");
        TryDelete(_dbPath + "-shm");
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public async Task AppendAndQuery_WithSessionId_RoundtripsValue()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var entry = new AuditEntry(
            Id: "id-1",
            Timestamp: DateTimeOffset.UtcNow,
            Hash: "h",
            PreviousHash: null,
            Severity: Severity.High,
            DetectorId: "AUTHZ-DENY",
            Summary: "denied",
            PolicyCode: "policy_denied",
            SessionId: "sess-roundtrip");

        await store.AppendAsync(entry, CancellationToken.None);

        AuditEntry? read = null;
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
        {
            read = e;
        }

        Assert.NotNull(read);
        Assert.Equal("sess-roundtrip", read!.SessionId);
    }

    [Fact]
    public async Task QueryWithSessionIdFilter_ReturnsOnlyEntriesForThatSession()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var sessionA = "sess-A-" + Guid.NewGuid().ToString("N");
        var sessionB = "sess-B-" + Guid.NewGuid().ToString("N");

        await store.AppendAsync(NewEntry("e-a-1", sessionA), CancellationToken.None);
        await store.AppendAsync(NewEntry("e-b-1", sessionB), CancellationToken.None);
        await store.AppendAsync(NewEntry("e-a-2", sessionA), CancellationToken.None);
        await store.AppendAsync(NewEntry("e-null", null),    CancellationToken.None);

        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(SessionId: sessionA), CancellationToken.None))
            results.Add(e);

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.Equal(sessionA, r.SessionId));
    }

    private static AuditEntry NewEntry(string id, string? sessionId) =>
        new(
            Id:           id,
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "h",
            PreviousHash: null,
            Severity:     Severity.Medium,
            DetectorId:   "SEC-01",
            Summary:      "test",
            PolicyCode:   null,
            SessionId:    sessionId);

    [Fact]
    public async Task AppendAndQuery_WithNullSessionId_RoundtripsNull()
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath });

        var entry = new AuditEntry(
            Id: "id-1",
            Timestamp: DateTimeOffset.UtcNow,
            Hash: "h",
            PreviousHash: null,
            Severity: Severity.High,
            DetectorId: "PromptInjection",
            Summary: "detection",
            PolicyCode: null,
            SessionId: null);

        await store.AppendAsync(entry, CancellationToken.None);

        AuditEntry? read = null;
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
        {
            read = e;
        }

        Assert.NotNull(read);
        Assert.Null(read!.SessionId);
    }
}
