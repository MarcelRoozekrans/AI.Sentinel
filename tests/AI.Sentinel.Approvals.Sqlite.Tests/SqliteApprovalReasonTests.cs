using System.Globalization;
using AI.Sentinel.Approvals;
using Microsoft.Data.Sqlite;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Approvals.Sqlite.Tests;

public sealed class SqliteApprovalReasonTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"approvals-reason-{Guid.NewGuid():N}.db"));

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

    private static ApprovalSpec MakeSpec() =>
        new() { PolicyName = "p", GrantDuration = TimeSpan.FromMinutes(15) };

    private static ApprovalContext MakeCtx(string? reason) =>
        new("delete_database", default, null) { Reason = reason };

    private sealed class TestSecurityContext(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private SqliteApprovalStore NewStore() =>
        new(new SqliteApprovalStoreOptions { DatabasePath = _dbPath, PollInterval = TimeSpan.FromMilliseconds(25) });

    private static async Task<List<PendingRequest>> ListAsync(SqliteApprovalStore store)
    {
        var list = new List<PendingRequest>();
        await foreach (var p in store.ListPendingAsync(TestContext.Current.CancellationToken))
        {
            list.Add(p);
        }
        return list;
    }

    [Fact]
    public async Task Reason_RoundTripsThroughListPending()
    {
        await using var store = NewStore();
        await store.EnsureRequestAsync(new TestSecurityContext("alice"), MakeSpec(), MakeCtx("Semantic match 0.91"), TestContext.Current.CancellationToken);

        var pending = Assert.Single(await ListAsync(store));
        Assert.Equal("Semantic match 0.91", pending.Reason);
    }

    [Fact]
    public async Task NullReason_StoredAsNull()
    {
        await using var store = NewStore();
        await store.EnsureRequestAsync(new TestSecurityContext("alice"), MakeSpec(), MakeCtx(null), TestContext.Current.CancellationToken);

        var pending = Assert.Single(await ListAsync(store));
        Assert.Null(pending.Reason);
    }

    [Fact]
    public async Task PendingState_CarriesStoredReason_OnCreateAndReuse_KeepingFirstReason()
    {
        await using var store = NewStore();
        var caller = new TestSecurityContext("alice");
        var created = await store.EnsureRequestAsync(caller, MakeSpec(), MakeCtx("first"), TestContext.Current.CancellationToken);
        var reused = await store.EnsureRequestAsync(caller, MakeSpec(), MakeCtx("second"), TestContext.Current.CancellationToken);

        Assert.Equal("first", Assert.IsType<ApprovalState.Pending>(created).Reason);
        Assert.Equal("first", Assert.IsType<ApprovalState.Pending>(reused).Reason);
        Assert.Equal("first", Assert.Single(await ListAsync(store)).Reason);
    }

    [Fact]
    public async Task V1Database_MigratesToV2_KeepingRows()
    {
        var csb = new SqliteConnectionStringBuilder { DataSource = _dbPath, Pooling = false };
        using (var conn = new SqliteConnection(csb.ToString()))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE approval_requests (
                    id TEXT PRIMARY KEY, caller_id TEXT NOT NULL, policy_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL, args_json TEXT NOT NULL, justification TEXT,
                    requested_at INTEGER NOT NULL, grant_duration_ticks INTEGER NOT NULL,
                    status TEXT NOT NULL, approved_at INTEGER, denied_at INTEGER,
                    deny_reason TEXT, approver_id TEXT, approver_note TEXT
                );
                INSERT INTO approval_requests (id, caller_id, policy_name, tool_name, args_json, requested_at, grant_duration_ticks, status)
                VALUES ('req-old', 'alice', 'p', 'tool', 'null', 638000000000000000, 9000000000, 'Pending');
                PRAGMA user_version = 1;
                """;
            cmd.ExecuteNonQuery();
        }

        await using (var store = NewStore())
        {
            var pending = Assert.Single(await ListAsync(store));
            Assert.Equal("req-old", pending.RequestId);
            Assert.Null(pending.Reason);
        }

        using var check = new SqliteConnection(csb.ToString());
        check.Open();
        using var ver = check.CreateCommand();
        ver.CommandText = "PRAGMA user_version;";
        Assert.Equal(2L, (long)ver.ExecuteScalar()!);
    }
}
