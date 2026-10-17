using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public sealed class SqliteAuditStoreReadOnlyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-ro-" + Guid.NewGuid().ToString("N"));

    public SqliteAuditStoreReadOnlyTests() => Directory.CreateDirectory(_dir);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    [Fact]
    public void OpenReadOnly_MissingFile_ThrowsAndCreatesNothing()
    {
        var db = Path.Combine(_dir, "sub", "missing.db");

        Assert.Throws<SqliteException>(() => SqliteAuditStore.OpenReadOnly(db));

        Assert.False(File.Exists(db));
        Assert.False(Directory.Exists(Path.Combine(_dir, "sub")));
    }

    [Fact]
    public async Task OpenReadOnly_ReadsTheEntries()
    {
        var db = await SeedAsync("SEC-01", "HAL-08");

        await using var store = SqliteAuditStore.OpenReadOnly(db);
        var ids = new List<string>();
        await foreach (var entry in store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, Ct))
        {
            ids.Add(entry.DetectorId);
        }

        Assert.Equal(["SEC-01", "HAL-08"], ids);
    }

    [Fact]
    public async Task OpenReadOnly_Append_Throws()
    {
        var db = await SeedAsync("SEC-01");

        await using var store = SqliteAuditStore.OpenReadOnly(db);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.AppendAsync(
            new AuditEntry("x", DateTimeOffset.UtcNow, "", null, Severity.Low, "SEC-01", "s"), Ct));
    }

    [Fact]
    public async Task OpenReadOnly_FileWithoutTheSchema_ThrowsAndLeavesItUnchanged()
    {
        var db = Path.Combine(_dir, "empty.db");
        await File.WriteAllBytesAsync(db, [], Ct);

        Assert.Throws<InvalidOperationException>(() => SqliteAuditStore.OpenReadOnly(db));

        Assert.Equal(0, new FileInfo(db).Length);
    }

    [Fact]
    public async Task OpenReadOnly_NotADatabase_Throws()
    {
        var db = Path.Combine(_dir, "garbage.db");
        await File.WriteAllTextAsync(db, "this is not a sqlite database, just some text padding it out a bit", Ct);

        Assert.Throws<SqliteException>(() => SqliteAuditStore.OpenReadOnly(db));
    }

    private async Task<string> SeedAsync(params string[] detectorIds)
    {
        var db = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        foreach (var id in detectorIds)
        {
            await store.AppendAsync(new AuditEntry(
                Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, "", null, Severity.High, id, "seeded " + id), Ct);
        }
        return db;
    }
}
