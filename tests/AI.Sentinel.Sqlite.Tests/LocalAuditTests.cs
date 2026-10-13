using System.Diagnostics;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite.Local;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

public sealed class LocalAuditTests : IDisposable
{
    private const string Hook = "SENTINEL_HOOK_";
    private const string Mcp = "SENTINEL_MCP_";
    private const long DefaultCap = 100L * 1024 * 1024;

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sentinel-local-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static Dictionary<string, string?> Env(params (string Key, string? Value)[] vars)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (key, value) in vars) env[key] = value;
        return env;
    }

    private static AuditEntry Make(string id) =>
        new(id, DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", $"summary-{id}");

    private static async Task<List<AuditEntry>> ReadAllAsync(IAuditStore store)
    {
        var results = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), TestContext.Current.CancellationToken))
        {
            results.Add(e);
        }
        return results;
    }

    [Fact]
    public void DefaultDatabasePath_IsUnderLocalApplicationData()
    {
        var expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ai-sentinel", "audit.db");
        Assert.Equal(expected, LocalAudit.DefaultDatabasePath());
    }

    [Fact]
    public void ReadSettings_Defaults()
    {
        var problems = new List<string>();
        var settings = LocalAudit.ReadSettings(Env(), Hook, "/default/audit.db", problems);

        Assert.Equal("/default/audit.db", settings.DatabasePath);
        Assert.Null(settings.NdjsonPath);
        Assert.Equal(DefaultCap, settings.MaxDatabaseSizeBytes);
        Assert.Empty(problems);
    }

    [Fact]
    public void ReadSettings_SqlitePath_OverridesTheDefault()
    {
        var problems = new List<string>();
        var settings = LocalAudit.ReadSettings(
            Env(("SENTINEL_HOOK_AUDIT_SQLITE", "/elsewhere/a.db")), Hook, "/default/audit.db", problems);

        Assert.Equal("/elsewhere/a.db", settings.DatabasePath);
        Assert.Empty(problems);
    }

    [Fact]
    public void ReadSettings_Off()
    {
        var problems = new List<string>();
        var settings = LocalAudit.ReadSettings(
            Env(("SENTINEL_HOOK_AUDIT_SQLITE", "OFF")), Hook, "/default/audit.db", problems);

        Assert.Null(settings.DatabasePath);
        Assert.Empty(problems);
    }

    [Fact]
    public void ReadSettings_MaxMbZero_MeansNoCap()
    {
        var problems = new List<string>();
        var settings = LocalAudit.ReadSettings(
            Env(("SENTINEL_HOOK_AUDIT_MAX_MB", "0")), Hook, "/default/audit.db", problems);

        Assert.Null(settings.MaxDatabaseSizeBytes);
        Assert.Empty(problems);
    }

    [Fact]
    public void ReadSettings_MaxMb_IsConvertedToBytes()
    {
        var problems = new List<string>();
        var settings = LocalAudit.ReadSettings(
            Env(("SENTINEL_HOOK_AUDIT_MAX_MB", "5")), Hook, "/default/audit.db", problems);

        Assert.Equal(5L * 1024 * 1024, settings.MaxDatabaseSizeBytes);
        Assert.Empty(problems);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("-5")]
    [InlineData("99999999999999999999")]
    public void ReadSettings_BadMaxMb_UsesDefaultAndReportsAProblem(string value)
    {
        var problems = new List<string>();
        var settings = LocalAudit.ReadSettings(
            Env(("SENTINEL_HOOK_AUDIT_MAX_MB", value)), Hook, "/default/audit.db", problems);

        Assert.Equal(DefaultCap, settings.MaxDatabaseSizeBytes);
        var problem = Assert.Single(problems);
        Assert.Contains("SENTINEL_HOOK_AUDIT_MAX_MB", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadSettings_UsesThePrefix()
    {
        var env = Env(("SENTINEL_MCP_AUDIT_NDJSON", "/logs/mcp.ndjson"));

        var withHook = LocalAudit.ReadSettings(env, Hook, "/default/audit.db", new List<string>());
        var withMcp = LocalAudit.ReadSettings(env, Mcp, "/default/audit.db", new List<string>());

        Assert.Null(withHook.NdjsonPath);
        Assert.Equal("/logs/mcp.ndjson", withMcp.NdjsonPath);
    }

    [Fact]
    public async Task Open_CreatesTheDatabaseAndTagsTheSource()
    {
        var dbPath = Path.Combine(_root, "ai-sentinel", "audit.db");
        await using var session = LocalAudit.Open(new LocalAuditSettings(dbPath, null, DefaultCap), AuditSources.Mcp);

        await session.Store.AppendAsync(Make("e1"), TestContext.Current.CancellationToken);
        await session.Store.AppendAsync(Make("e2"), TestContext.Current.CancellationToken);

        Assert.True(File.Exists(dbPath));
        Assert.Empty(session.Problems);
        var entries = await ReadAllAsync(session.Store);
        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.Equal("mcp", e.Source));
        var verification = await AuditHashChain.VerifyAsync(
            session.Store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), TestContext.Current.CancellationToken),
            TestContext.Current.CancellationToken);
        Assert.True(verification.IsIntact);
        Assert.Equal(2, verification.EntriesChecked);
    }

    [Fact]
    public async Task Open_OnUnix_CreatesPrivateDirectoryAndFile()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Unix file modes do not apply on Windows.");
            return;
        }

        var dir = Path.Combine(_root, "ai-sentinel");
        var dbPath = Path.Combine(dir, "audit.db");
        var ndjsonPath = Path.Combine(dir, "audit.ndjson");
        await using (var session = LocalAudit.Open(new LocalAuditSettings(dbPath, ndjsonPath, DefaultCap), AuditSources.ClaudeCode))
        {
            await session.Store.AppendAsync(Make("e1"), TestContext.Current.CancellationToken);
            Assert.Empty(session.Problems);
        }

        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.Equal(ownerOnly | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
        Assert.Equal(ownerOnly, File.GetUnixFileMode(dbPath));
        Assert.Equal(ownerOnly, File.GetUnixFileMode(ndjsonPath));
    }

    [Fact]
    public async Task Open_OnUnix_LeavesAnExistingDirectoryAlone()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Unix file modes do not apply on Windows.");
            return;
        }

        const UnixFileMode shared = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute;
        Directory.CreateDirectory(_root);
        File.SetUnixFileMode(_root, shared);

        await using (var session = LocalAudit.Open(
            new LocalAuditSettings(Path.Combine(_root, "audit.db"), null, DefaultCap), AuditSources.ClaudeCode))
        {
            Assert.Empty(session.Problems);
        }

        Assert.Equal(shared, File.GetUnixFileMode(_root));
    }

    [Fact]
    public async Task Open_SqliteOff_UsesTheRingBuffer()
    {
        await using var session = LocalAudit.Open(new LocalAuditSettings(null, null, DefaultCap), AuditSources.Copilot);

        var stored = await session.Store.AppendAsync(Make("e1"), TestContext.Current.CancellationToken);

        Assert.Equal("copilot", stored.Source);
        Assert.Single(await ReadAllAsync(session.Store));
        Assert.Empty(session.Problems);
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public async Task Open_PathIsADirectory_FallsBackToRingBufferAndReportsAProblem()
    {
        var dbPath = Path.Combine(_root, "is-a-directory");
        Directory.CreateDirectory(dbPath);

        await using var session = LocalAudit.Open(new LocalAuditSettings(dbPath, null, DefaultCap), AuditSources.Mcp);
        var stored = await session.Store.AppendAsync(Make("e1"), TestContext.Current.CancellationToken);

        Assert.Single(session.Problems);
        Assert.Equal("mcp", stored.Source);
        Assert.False(string.IsNullOrEmpty(stored.Hash));
        Assert.Single(await ReadAllAsync(session.Store));
    }

    [Fact]
    public async Task Open_NdjsonPathUnusable_SkipsNdjsonAndReportsAProblem()
    {
        var ndjsonPath = Path.Combine(_root, "is-a-directory");
        Directory.CreateDirectory(ndjsonPath);

        await using var session = LocalAudit.Open(new LocalAuditSettings(null, ndjsonPath, DefaultCap), AuditSources.Mcp);

        Assert.Empty(session.Forwarders);
        Assert.Single(session.Problems);
    }

    [Fact]
    public async Task Store_AppendFailure_IsReportedNotThrown()
    {
        var problems = new List<string>();
        var store = new SourceTaggingAuditStore(new ThrowingAuditStore(), AuditSources.ClaudeCode, problems.Add);

        var returned = await store.AppendAsync(Make("e1"), TestContext.Current.CancellationToken);

        Assert.Equal("e1", returned.Id);
        Assert.Equal("claude-code", returned.Source);
        Assert.Single(problems);
        Assert.Equal(1, store.AppendCount);
    }

    [Fact]
    public async Task Open_NdjsonSendFailure_BecomesASessionProblem()
    {
        var ndjsonPath = Path.Combine(_root, "audit.ndjson");
        Directory.CreateDirectory(_root);
        var session = LocalAudit.Open(new LocalAuditSettings(null, ndjsonPath, DefaultCap), AuditSources.ClaudeCode);
        var forwarder = Assert.Single(session.Forwarders);
        await session.DisposeAsync();

        await forwarder.SendAsync([Make("e1")], TestContext.Current.CancellationToken);

        var problem = Assert.Single(session.Problems);
        Assert.Contains("send_dropped", problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Session_AppendFailure_BecomesASessionProblem()
    {
        await using var session = new LocalAuditSession(new ThrowingAuditStore(), AuditSources.Mcp, [], new LocalAuditProblems());

        await session.Store.AppendAsync(Make("e1"), TestContext.Current.CancellationToken);

        var problem = Assert.Single(session.Problems);
        Assert.Contains("disk full", problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisposeAsync_ForwarderDisposeThrows_StillDisposesTheStoreAndReports()
    {
        var store = new DisposalRecordingStore();
        var session = new LocalAuditSession(store, AuditSources.Mcp, [new ThrowingDisposeForwarder()], new LocalAuditProblems());

        await session.DisposeAsync();

        Assert.True(store.Disposed);
        var problem = Assert.Single(session.Problems);
        Assert.Contains("dispose failed", problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisposeAsync_StoreDisposeThrows_ReturnsNormallyAndReports()
    {
        var session = new LocalAuditSession(
            new DisposalRecordingStore(throwOnDispose: true), AuditSources.Mcp, [], new LocalAuditProblems());

        await session.DisposeAsync();

        Assert.Single(session.Problems);
    }

    [Fact]
    public async Task FlushAsync_WaitsForASendThatHasNotStartedYet()
    {
        var slow = new RecordingForwarder(TimeSpan.FromMilliseconds(300));
        await using var session = new LocalAuditSession(new RingBufferAuditStore(), AuditSources.Mcp, [slow], new LocalAuditProblems());

        await session.Store.AppendAndForwardAsync(
            Make("e1"), AuditForwarding.Snapshot(session.Forwarders), TestContext.Current.CancellationToken);
        await session.FlushAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(1, slow.Recorded);
    }

    [Fact]
    public async Task FlushAsync_ThrowingForwarder_DoesNotWaitForTheTimeout()
    {
        await using var session = new LocalAuditSession(
            new RingBufferAuditStore(), AuditSources.Mcp, [new ThrowingForwarder()], new LocalAuditProblems());

        await session.Store.AppendAndForwardAsync(
            Make("e1"), AuditForwarding.Snapshot(session.Forwarders), TestContext.Current.CancellationToken);
        var sw = Stopwatch.StartNew();
        await session.FlushAsync(TimeSpan.FromSeconds(10));

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Flush took {sw.Elapsed}.");
    }

    [Fact]
    public async Task FlushAsync_WaitsForNdjsonLines()
    {
        var dbPath = Path.Combine(_root, "audit.db");
        var ndjsonPath = Path.Combine(_root, "audit.ndjson");
        Directory.CreateDirectory(_root);
        await using var session = LocalAudit.Open(new LocalAuditSettings(dbPath, ndjsonPath, DefaultCap), AuditSources.Mcp);

        await session.Store.AppendAndForwardAsync(
            Make("e1"), AuditForwarding.Snapshot(session.Forwarders), TestContext.Current.CancellationToken);
        await session.FlushAsync(TimeSpan.FromSeconds(10));

        await using var stream = new FileStream(ndjsonPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        var content = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var line = Assert.Single(lines);
        Assert.Contains("\"e1\"", line, StringComparison.Ordinal);
        Assert.Empty(session.Problems);
    }

    private sealed class ThrowingAuditStore : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) =>
            throw new IOException("disk full");

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) =>
            throw new IOException("disk full");
    }

    private sealed class DisposalRecordingStore(bool throwOnDispose = false) : IAuditStore, IAsyncDisposable
    {
        private readonly RingBufferAuditStore _inner = new();

        public bool Disposed { get; private set; }

        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) => _inner.AppendAsync(entry, ct);

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) => _inner.QueryAsync(query, ct);

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            _inner.Dispose();
            return throwOnDispose ? ValueTask.FromException(new IOException("store dispose failed")) : ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingDisposeForwarder : IAuditForwarder, IAsyncDisposable
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct) => ValueTask.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.FromException(new IOException("forwarder dispose failed"));
    }

    private sealed class RecordingForwarder(TimeSpan delay) : IAuditForwarder
    {
        private int _recorded;

        public int Recorded => Volatile.Read(ref _recorded);

        public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            await Task.Delay(delay, ct);
            Interlocked.Add(ref _recorded, batch.Count);
        }
    }

    private sealed class ThrowingForwarder : IAuditForwarder
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct) =>
            throw new InvalidOperationException("broken forwarder");
    }
}
