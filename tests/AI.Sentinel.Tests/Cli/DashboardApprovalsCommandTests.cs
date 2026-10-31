using System.Net;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Audit;
using AI.Sentinel.Cli;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using Microsoft.Data.Sqlite;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Cli;

public class DashboardApprovalsCommandTests : IDisposable
{
    private const string Tool = "delete_database";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-dashapprove-" + Guid.NewGuid().ToString("N"));

    public DashboardApprovalsCommandTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string ApprovalsDb => Path.Combine(_dir, "approvals.db");

    [Fact]
    public async Task Sqlite_LocalApprover_ApproveIsRecordedOnceInTheAuditChain()
    {
        var (db, config) = await SeedAsync("sqlite");
        var id = await CreatePendingAsync();
        var stdout = new StringWriter();
        await using var dashboard = await StartAsync(db, config, stdout, new StringWriter(), s => s);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();

        var first = await http.PostAsync(new Uri(dashboard.Url, $"api/approvals/{id}/approve"), new StringContent(""), Ct);
        var second = await http.PostAsync(new Uri(dashboard.Url, $"api/approvals/{id}/approve"), new StringContent(""), Ct);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.True((int)second.StatusCode < 500, $"second approve gave {second.StatusCode}");
        Assert.Equal(("Active", Environment.UserName), ReadRequest(id));
        var entries = await ReadAuditAsync(db);
        Assert.Single(entries, e => string.Equals(e.PolicyCode, "APPROVED", StringComparison.Ordinal));
        Assert.True((await AuditHashChain.VerifyAsync(ToAsync(entries), Ct)).IsIntact);
        Assert.Contains($"Approvals: sqlite {ApprovalsDb}, approver is the local user {Environment.UserName}", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sqlite_TrustedProxy_DenyRecordsHeaderUserAndReason()
    {
        var (db, config) = await SeedAsync("sqlite");
        var id = await CreatePendingAsync();
        var stdout = new StringWriter();
        await using var dashboard = await StartAsync(db, config, stdout, new StringWriter(), s => s, proxy: true);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(dashboard.Url, $"api/approvals/{id}/deny"))
        {
            Content = new FormUrlEncodedContent([new("reason", "too risky")]),
        };
        req.Headers.Add("X-Auth-Request-User", "carol-secret-name");

        var resp = await http.SendAsync(req, Ct);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(("Denied", "carol-secret-name"), ReadRequest(id));
        Assert.Single(await ReadAuditAsync(db), e => string.Equals(e.PolicyCode, "DENIED", StringComparison.Ordinal));
        Assert.DoesNotContain("carol-secret-name", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task StartupLine_NeverPrintsHeaderValues()
    {
        var (db, config) = await SeedAsync("sqlite");
        var stdout = new StringWriter();
        await using var dashboard = await StartAsync(db, config, stdout, new StringWriter(), s => s, proxy: true);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(dashboard.Url, "api/approvals"));
        req.Headers.Add("X-Auth-Request-User", "carol-secret-name");
        await http.SendAsync(req, Ct);

        var text = stdout.ToString();
        Assert.Contains($"Approvals: sqlite {ApprovalsDb}, approver from X-Auth-Request-User via 127.0.0.1/32", text, StringComparison.Ordinal);
        Assert.DoesNotContain("carol-secret-name", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sqlite_NoApproverConfigured_ApproveIs401AndAuditUnchanged()
    {
        var (db, config) = await SeedAsync("sqlite");
        var id = await CreatePendingAsync();
        var stdout = new StringWriter();
        await using var dashboard = await StartAsync(db, config, stdout, new StringWriter(), s => s, localApprover: false);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();

        var resp = await http.PostAsync(new Uri(dashboard.Url, $"api/approvals/{id}/approve"), new StringContent(""), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal(("Pending", null), ReadRequest(id));
        Assert.DoesNotContain(await ReadAuditAsync(db), e => string.Equals(e.PolicyCode, "APPROVED", StringComparison.Ordinal));
        Assert.Contains("no approver configured, so approve and deny are refused", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sqlite_PanelListsThePendingRequest()
    {
        var (db, config) = await SeedAsync("sqlite");
        await CreatePendingAsync();
        await using var dashboard = await StartAsync(db, config, new StringWriter(), new StringWriter(), s => s);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();

        var body = await http.GetStringAsync(new Uri(dashboard.Url, "api/approvals"), Ct);

        Assert.Contains(Tool, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoApprovalConfig_AuditFileStaysReadOnly()
    {
        var (db, _) = await SeedAsync("sqlite");
        var before = await File.ReadAllBytesAsync(db, Ct);
        var stdout = new StringWriter();
        var dashboard = await StartAsync(db, null, stdout, new StringWriter(), s => s);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();
        var resp = await http.PostAsync(new Uri(dashboard.Url, "api/approvals/x/approve"), new StringContent(""), Ct);
        await dashboard.DisposeAsync();

        Assert.False(resp.IsSuccessStatusCode);
        Assert.Equal(before, await File.ReadAllBytesAsync(db, Ct));
        Assert.Contains("Approvals: off", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EntraPim_ShowsExternalMessage_AndDoesNotWrite()
    {
        var (db, config) = await SeedAsync("entra-pim");
        var before = await File.ReadAllBytesAsync(db, Ct);
        var stdout = new StringWriter();
        var dashboard = await StartAsync(db, config, stdout, new StringWriter(), s => s);
        Assert.NotNull(dashboard);
        using var http = new HttpClient();
        var body = await http.GetStringAsync(new Uri(dashboard.Url, "api/approvals"), Ct);
        await dashboard.DisposeAsync();

        Assert.Contains("PIM portal", body, StringComparison.Ordinal);
        Assert.Equal(before, await File.ReadAllBytesAsync(db, Ct));
        Assert.Contains("Approvals: managed in Entra PIM", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task InMemory_Explicit_ExitsWithError()
    {
        var (db, config) = await SeedAsync("in-memory");
        var stderr = new StringWriter();

        var dashboard = await StartAsync(db, config, new StringWriter(), stderr, s => s with { ApprovalConfigExplicit = true });

        Assert.Null(dashboard);
        Assert.Contains("in-memory", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task InMemory_FromEnvironment_NotesAndContinues()
    {
        var (db, config) = await SeedAsync("in-memory");
        var stdout = new StringWriter();

        await using var dashboard = await StartAsync(db, config, stdout, new StringWriter(), s => s with { ApprovalConfigExplicit = false });

        Assert.NotNull(dashboard);
        Assert.Contains("Approvals: off (", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TrustedProxyWithoutApprovals_NotesNothingToApprove()
    {
        var (db, _) = await SeedAsync("sqlite");
        var stdout = new StringWriter();

        await using var dashboard = await StartAsync(db, null, stdout, new StringWriter(), s => s, proxy: true);

        Assert.NotNull(dashboard);
        Assert.Contains(
            "Approvals: off (no approval config, so --trusted-proxy has nothing to approve)", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BrokenConfig_ReturnsNullWithPath()
    {
        var (db, _) = await SeedAsync("sqlite");
        var config = Path.Combine(_dir, "broken.json");
        await File.WriteAllTextAsync(config, "{ not json", Ct);
        var stderr = new StringWriter();

        var dashboard = await StartAsync(db, config, new StringWriter(), stderr, s => s);

        Assert.Null(dashboard);
        Assert.Contains($"Could not load the approval config {config}:", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task OlderAuditSchema_WithApprovals_StillRefused()
    {
        var (db, config) = await SeedAsync("sqlite");
        using (var conn = new SqliteConnection($"Data Source={db};Pooling=False"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA user_version = 1;";
            cmd.ExecuteNonQuery();
        }
        var stderr = new StringWriter();

        var dashboard = await StartAsync(db, config, new StringWriter(), stderr, s => s);

        Assert.Null(dashboard);
        Assert.Contains("older", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RootApprovalLink_RedirectsUnderThePrefix()
    {
        var (db, config) = await SeedAsync("sqlite");
        await using var dashboard = await StartAsync(db, config, new StringWriter(), new StringWriter(), s => s);
        Assert.NotNull(dashboard);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });

        var resp = await http.GetAsync(new Uri(dashboard.Url, "/approvals/a%2Fb"), Ct);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.EndsWith("/ai-sentinel/approvals/a%2Fb", resp.Headers.Location?.OriginalString, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dispose_ReleasesTheApprovalDatabase()
    {
        var (db, config) = await SeedAsync("sqlite");
        await CreatePendingAsync();
        var dashboard = await StartAsync(db, config, new StringWriter(), new StringWriter(), s => s);
        Assert.NotNull(dashboard);
        using (var http = new HttpClient())
        {
            await http.GetStringAsync(new Uri(dashboard.Url, "api/approvals"), Ct);
        }

        await dashboard.DisposeAsync();
        SqliteConnection.ClearAllPools();

        File.Delete(ApprovalsDb);
        Assert.False(File.Exists(ApprovalsDb));
    }

    [Fact]
    public async Task NonLoopbackBind_WithProxy_StillServesLoopbackRequests()
    {
        var (db, config) = await SeedAsync("sqlite");
        await using var dashboard = await StartAsync(
            db, config, new StringWriter(), new StringWriter(), s => s with { Bind = IPAddress.Any }, proxy: true, proxyCidr: "10.0.0.0/8");
        Assert.NotNull(dashboard);
        using var http = new HttpClient();

        var resp = await http.GetAsync(new Uri(dashboard.Url, "api/approvals"), Ct);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private async Task<RunningDashboard?> StartAsync(
        string db, string? config, StringWriter stdout, StringWriter stderr, Func<DashboardSettings, DashboardSettings> tweak,
        bool proxy = false, bool localApprover = true, string proxyCidr = "127.0.0.1/32")
    {
        var settings = new DashboardSettings(db, 0)
        {
            ApprovalConfigPath = config,
            ApprovalConfigExplicit = config is not null,
            TrustedProxies = proxy ? [IPNetwork.Parse(proxyCidr)] : [],
            LocalApprover = localApprover && !proxy,
        };
        return await DashboardCommand.StartAsync(tweak(settings), stdout, stderr, Ct);
    }

    private async Task<(string Db, string Config)> SeedAsync(string backend)
    {
        var db = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db }))
        {
            await store.AppendAsync(new AuditEntry(
                Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, "", null, Severity.High, "SEC-01", "seeded"), Ct);
        }
        var config = Path.Combine(_dir, "approvals-" + backend + ".json");
        var json = backend switch
        {
            "sqlite" => JsonSerializer.Serialize(new { backend, databasePath = ApprovalsDb }),
            "entra-pim" => JsonSerializer.Serialize(new { backend, tenantId = "00000000-0000-0000-0000-000000000000" }),
            _ => JsonSerializer.Serialize(new { backend }),
        };
        await File.WriteAllTextAsync(config, json, Ct);
        return (db, config);
    }

    private async Task<string> CreatePendingAsync()
    {
        await using var store = new SqliteApprovalStore(new SqliteApprovalStoreOptions { DatabasePath = ApprovalsDb });
        using var doc = JsonDocument.Parse("""{"target":"prod"}""");
        var state = await store.EnsureRequestAsync(
            new Caller("agent-1"), new ApprovalSpec { PolicyName = "p", GrantDuration = TimeSpan.FromMinutes(15) },
            new ApprovalContext(Tool, doc.RootElement.Clone(), "cleanup"), Ct);
        return Assert.IsType<ApprovalState.Pending>(state).RequestId;
    }

    private (string Status, string? Approver) ReadRequest(string id)
    {
        using var conn = new SqliteConnection($"Data Source={ApprovalsDb};Mode=ReadOnly;Pooling=False");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT status, approver_id FROM approval_requests WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        using var reader = cmd.ExecuteReader();
        Assert.True(reader.Read());
        return (reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1));
    }

    private static async Task<List<AuditEntry>> ReadAuditAsync(string db)
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        var list = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, Ct))
        {
            list.Add(e);
        }
        return list;
    }

    private static async IAsyncEnumerable<AuditEntry> ToAsync(IEnumerable<AuditEntry> entries)
    {
        foreach (var e in entries)
        {
            yield return e;
        }
        await Task.CompletedTask;
    }

    private sealed class Caller(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }
}
