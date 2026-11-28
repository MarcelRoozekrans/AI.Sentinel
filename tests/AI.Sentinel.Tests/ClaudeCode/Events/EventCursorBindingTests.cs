using System.Globalization;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode.Events;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>The cursor is bound to the server and organisation it sends to (#723) and to the audit file it reads (#713). An entry never
/// reaches a server it was not routed for, a replaced file is sent from its oldest entry, and every gap is reported once.</summary>
[Collection("NonParallel")]
public sealed class EventCursorBindingTests : IDisposable
{
    private static readonly Uri ServerA = new("https://sentinel.example.com/ai-sentinel/events/ingest");
    private static readonly Uri ServerB = new("https://other.example.org/ai-sentinel/events/ingest");

    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly string _db;
    private readonly EventServerStub _a = new();
    private readonly EventServerStub _b = new();
    private readonly List<string> _log = [];
    private string _organisation = "acme";

    public EventCursorBindingTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "audit.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        ResidentTestSupport.Delete(_dir);
    }

    private string CursorPath => Path.Combine(_dir, EventCursor.FileName);

    private EventForwarder To(EventServerStub server, Uri endpoint, string? db = null, int batchSize = 200) => new(
        new SqliteAuditSource(db ?? _db), new EventCursor(_dir), new HttpClient(server), endpoint, () => _organisation, _ => false, _log.Add,
        batchSize);

    private async Task AppendAsync(int count, string? db = null, string? toolKind = "shell")
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db ?? _db });
        for (var i = 0; i < count; i++)
        {
            await store.AppendAsync(
                new AuditEntry(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", $"e{i}")
                {
                    ToolKind = toolKind,
                    Node = "node-a",
                    SessionId = "s-1",
                    Source = "claude-code",
                },
                CancellationToken.None);
        }
    }

    private async Task ExecuteAsync(string sql, string? db = null)
    {
        await using var connection = new SqliteConnection($"Data Source={db ?? _db};Pooling=False");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static void DeleteDatabase(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var file in new[] { path, path + "-wal", path + "-shm" })
        {
            File.Delete(file);
        }
    }

    private static JsonElement Gap(JsonElement batch) => batch.GetProperty("gap");

    // The next batch the server takes is followed by a cursor write that fails: the cursor keeps what it held before that write.
    private byte[]? _kept;

    private void LoseTheNextCursorWrite(EventServerStub server) => server.AfterTaken = () =>
    {
        server.AfterTaken = null;
        _kept = File.ReadAllBytes(CursorPath);
        File.Delete(CursorPath);
        Directory.CreateDirectory(CursorPath);
    };

    private void RepairTheCursor()
    {
        Directory.Delete(CursorPath);
        File.WriteAllBytes(CursorPath, _kept!);
    }

    [Fact]
    public async Task Unsent_entries_recorded_for_another_server_are_skipped_and_reported_to_the_new_one_as_a_gap()
    {
        await AppendAsync(2);
        Assert.Equal(2, (await To(_a, ServerA).ForwardAsync(CancellationToken.None)).Sent);
        await AppendAsync(3);

        var result = await To(_b, ServerB).ForwardAsync(CancellationToken.None);

        Assert.False(result.Failed);
        Assert.Equal(0, result.Sent);
        Assert.Empty(_b.Events);
        var gap = Gap(Assert.Single(_b.Batches));
        Assert.Equal(3, gap.GetProperty("pruned").GetInt32());
        Assert.Equal("server_change", gap.GetProperty("cause").GetString());
        Assert.False(string.IsNullOrEmpty(gap.GetProperty("id").GetString()));
        Assert.Contains(_log, line => line.StartsWith("the server or organisation changed", StringComparison.Ordinal));
        Assert.Equal(2, _a.Events.Count());

        await AppendAsync(1);
        Assert.Equal(1, (await To(_b, ServerB).ForwardAsync(CancellationToken.None)).Sent);
        Assert.Single(_b.Events);
    }

    [Fact]
    public async Task A_skip_counts_the_routed_entries_and_the_pruned_ones_but_not_those_that_were_never_routed()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(2);
        await AppendAsync(2, toolKind: null);
        await ExecuteAsync("DELETE FROM audit_entries WHERE sequence <= 2;");

        await To(_b, ServerB).ForwardAsync(CancellationToken.None);

        Assert.Equal(2, Gap(Assert.Single(_b.Batches)).GetProperty("pruned").GetInt32());
        Assert.Contains(_log, line => line.Contains("2 unsent entries", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_server_change_together_with_a_replaced_file_skips_the_new_file_and_reports_a_gap_of_unknown_size()
    {
        await AppendAsync(2);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        DeleteDatabase(_db);
        await AppendAsync(3);

        var result = await To(_b, ServerB).ForwardAsync(CancellationToken.None);

        Assert.Equal(0, result.Sent);
        var gap = Gap(Assert.Single(_b.Batches));
        Assert.True(gap.GetProperty("unknown").GetBoolean());
        Assert.Equal("server_change", gap.GetProperty("cause").GetString());
        Assert.Contains(_log, line => line.EndsWith("gap of unknown size", StringComparison.Ordinal));
        Assert.Equal(3, new EventCursor(_dir).Read());
    }

    [Fact]
    public async Task A_server_change_with_nothing_unsent_reports_no_gap()
    {
        await AppendAsync(2);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        var result = await To(_b, ServerB).ForwardAsync(CancellationToken.None);

        Assert.False(result.Failed);
        Assert.Empty(_b.Batches);
        await AppendAsync(1);
        Assert.Equal(1, (await To(_b, ServerB).ForwardAsync(CancellationToken.None)).Sent);
    }

    [Fact]
    public async Task Another_organisation_on_the_same_server_also_skips_the_unsent_entries()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(2);
        _organisation = "globex";

        await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        var last = _a.Batches[^1];
        Assert.Equal("globex", last.GetProperty("organisation").GetString());
        Assert.Empty(last.GetProperty("events").EnumerateArray());
        Assert.Equal(2, Gap(last).GetProperty("pruned").GetInt32());
        Assert.Single(_a.Events);
    }

    [Fact]
    public async Task A_cursor_from_an_older_version_names_no_server_so_its_unsent_entries_are_skipped()
    {
        await AppendAsync(3);
        string hash;
        await using (var store = SqliteAuditStore.OpenReadOnly(_db))
        {
            hash = (await store.ReadAfterAsync(0, 1, CancellationToken.None)).Rows[0].Entry.Hash;
        }

        PolicyCache.Write(CursorPath, Encoding.UTF8.GetBytes($$"""{"sequence":1,"hash":"{{hash}}"}"""));

        var result = await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        Assert.Equal(0, result.Sent);
        Assert.Equal(2, Gap(Assert.Single(_a.Batches)).GetProperty("pruned").GetInt32());
        Assert.Equal(3, new EventCursor(_dir).Read());
    }

    [Fact]
    public async Task A_skip_gap_that_the_server_refused_is_sent_again_with_the_same_id()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(2);
        _b.Status = System.Net.HttpStatusCode.ServiceUnavailable;
        Assert.True((await To(_b, ServerB).ForwardAsync(CancellationToken.None)).Failed);
        _b.Status = System.Net.HttpStatusCode.OK;

        await To(_b, ServerB).ForwardAsync(CancellationToken.None);

        Assert.Equal(2, _b.Requests.Count);
        Assert.Equal(Gap(_b.Requests[0]).GetProperty("id").GetString(), Gap(_b.Requests[1]).GetProperty("id").GetString());
        Assert.Empty(_b.Events);
    }

    [Fact]
    public async Task A_gap_whose_cursor_could_not_be_stored_is_sent_again_with_the_same_id()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(2);
        LoseTheNextCursorWrite(_b);
        Assert.True((await To(_b, ServerB).ForwardAsync(CancellationToken.None)).Failed);
        RepairTheCursor();

        await To(_b, ServerB).ForwardAsync(CancellationToken.None);

        Assert.Empty(_b.Events);
        Assert.Equal(2, _b.Batches.Count);
        Assert.Equal(Gap(_b.Batches[0]).GetProperty("id").GetString(), Gap(_b.Batches[1]).GetProperty("id").GetString());
    }

    [Fact]
    public async Task A_pruned_gap_sent_again_after_a_lost_cursor_keeps_its_id()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(3);
        await ExecuteAsync("DELETE FROM audit_entries WHERE sequence <= 3;");
        LoseTheNextCursorWrite(_a);
        Assert.True((await To(_a, ServerA).ForwardAsync(CancellationToken.None)).Failed);
        RepairTheCursor();

        await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        var gaps = _a.Batches.Where(b => b.TryGetProperty("gap", out _)).Select(Gap).ToList();
        Assert.Equal(2, gaps.Count);
        Assert.Equal(2, gaps[0].GetProperty("pruned").GetInt32());
        Assert.Equal("pruned", gaps[0].GetProperty("cause").GetString());
        Assert.False(string.IsNullOrEmpty(gaps[0].GetProperty("id").GetString()));
        Assert.Equal(gaps[0].GetProperty("id").GetString(), gaps[1].GetProperty("id").GetString());
    }

    [Fact]
    public async Task A_sign_in_to_another_organisation_during_a_pass_sends_nothing_more_to_the_old_one()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(3);
        _a.AfterTaken = () =>
        {
            _a.AfterTaken = null;
            _organisation = "globex";
        };

        var result = await To(_a, ServerA, batchSize: 1).ForwardAsync(CancellationToken.None);

        Assert.False(result.Failed);
        Assert.Equal(1, result.Sent);
        Assert.Equal(2, _a.Events.Count());
        Assert.All(_a.Batches, b => Assert.Equal("acme", b.GetProperty("organisation").GetString()));

        await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        var last = _a.Batches[^1];
        Assert.Equal("globex", last.GetProperty("organisation").GetString());
        Assert.Equal(2, Gap(last).GetProperty("pruned").GetInt32());
        Assert.Equal(2, _a.Events.Count());
    }

    [Fact]
    public async Task A_stored_pruned_gap_is_sent_again_unchanged_even_when_retention_pruned_more_since()
    {
        await AppendAsync(1);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(3);
        await ExecuteAsync("DELETE FROM audit_entries WHERE sequence <= 3;");
        LoseTheNextCursorWrite(_a);
        Assert.True((await To(_a, ServerA).ForwardAsync(CancellationToken.None)).Failed);
        RepairTheCursor();
        await AppendAsync(1);
        await ExecuteAsync("DELETE FROM audit_entries WHERE sequence <= 4;");

        var result = await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        var gaps = _a.Batches.Where(b => b.TryGetProperty("gap", out _)).Select(Gap).ToList();
        Assert.Equal(3, gaps.Count);
        Assert.Equal(gaps[0].GetProperty("id").GetString(), gaps[1].GetProperty("id").GetString());
        Assert.Equal(2, gaps[1].GetProperty("pruned").GetInt32());
        Assert.NotEqual(gaps[1].GetProperty("id").GetString(), gaps[2].GetProperty("id").GetString(), StringComparer.Ordinal);
        Assert.Equal(1, gaps[2].GetProperty("pruned").GetInt32());
        Assert.Equal(3, result.Pruned);
        Assert.Equal(1, result.Sent);
    }

    [Fact]
    public async Task Unsent_entries_that_retention_deleted_from_an_emptied_audit_are_reported_from_the_counter()
    {
        await AppendAsync(2);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(3);
        await ExecuteAsync("DELETE FROM audit_entries;");

        var result = await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        Assert.Equal(0, result.Sent);
        Assert.Equal(3, result.Pruned);
        var gap = Gap(_a.Batches[^1]);
        Assert.Equal(3, gap.GetProperty("pruned").GetInt32());
        Assert.Equal("pruned", gap.GetProperty("cause").GetString());
        Assert.Equal(5, new EventCursor(_dir).Read());

        await AppendAsync(1);
        var next = await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        Assert.Equal(1, next.Sent);
        Assert.Equal(0, next.Pruned);
    }

    [Fact]
    public async Task A_replaced_audit_file_is_sent_from_its_oldest_entry_with_a_gap_of_unknown_size()
    {
        await AppendAsync(3);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        DeleteDatabase(_db);
        await AppendAsync(2);
        await ExecuteAsync("DELETE FROM audit_entries WHERE sequence = 1;");

        var result = await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        Assert.Equal(1, result.Sent);
        Assert.Equal(4, _a.Events.Count());
        var gaps = _a.Batches.Where(b => b.TryGetProperty("gap", out _)).Select(Gap).ToList();
        var gap = Assert.Single(gaps);
        Assert.True(gap.GetProperty("unknown").GetBoolean());
        Assert.False(gap.TryGetProperty("pruned", out _));
        Assert.Equal("audit_replaced", gap.GetProperty("cause").GetString());
        Assert.Contains(_log, line => line.StartsWith("the audit file was replaced", StringComparison.Ordinal));
        Assert.Equal(2, new EventCursor(_dir).Read());
    }

    [Fact]
    public async Task A_copy_of_the_audit_restored_from_before_the_cursor_reads_as_replaced()
    {
        await AppendAsync(2);
        var copy = Path.Combine(_dir, "copy.db");
        SqliteConnection.ClearAllPools();
        await ExecuteAsync(string.Create(CultureInfo.InvariantCulture, $"VACUUM INTO '{copy}';"));
        await AppendAsync(2);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        DeleteDatabase(_db);
        File.Move(copy, _db);

        await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        Assert.True(Gap(Assert.Single(_a.Batches, b => b.TryGetProperty("gap", out _))).GetProperty("unknown").GetBoolean());
        Assert.Equal(6, _a.Events.Count());
        Assert.Equal(2, new EventCursor(_dir).Read());
    }

    [Fact]
    public async Task The_same_file_and_server_reports_no_gap_and_sends_each_entry_once()
    {
        await AppendAsync(2);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);
        await AppendAsync(2);
        await To(_a, ServerA).ForwardAsync(CancellationToken.None);

        Assert.Equal(4, _a.Events.Count());
        Assert.All(_a.Batches, b => Assert.False(b.TryGetProperty("gap", out _)));
        Assert.Empty(_log);
    }
}
