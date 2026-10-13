using System.Net;
using System.Net.Sockets;
using AI.Sentinel.Audit;
using AI.Sentinel.Cli;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

public class DashboardCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-dashboard-" + Guid.NewGuid().ToString("N"));

    public DashboardCommandTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    [Fact]
    public async Task Start_ServesTheFeedFromAnExistingFile()
    {
        var db = await SeedAsync("SEC-01", "HAL-08");

        await using var dashboard = await DashboardCommand.StartAsync(
            db, 0, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

        Assert.NotNull(dashboard);
        using var http = new HttpClient();
        var resp = await http.GetAsync(new Uri(dashboard.Url, "api/feed"), TestContext.Current.CancellationToken);
        var body = await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("SEC-01", body, StringComparison.Ordinal);
        Assert.Contains("HAL-08", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Start_MissingFile_ReturnsNullAndCreatesNothing()
    {
        var db = Path.Combine(_dir, "missing.db");
        var stderr = new StringWriter();

        var dashboard = await DashboardCommand.StartAsync(
            db, 0, new StringWriter(), stderr, TestContext.Current.CancellationToken);

        Assert.Null(dashboard);
        Assert.False(File.Exists(db));
        Assert.Contains(db, stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Start_DoesNotAppend()
    {
        var db = await SeedAsync("SEC-01", "HAL-08");
        var before = await SnapshotAsync(db);

        var dashboard = await DashboardCommand.StartAsync(
            db, 0, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);
        Assert.NotNull(dashboard);
        try
        {
            using var http = new HttpClient();
            for (var i = 0; i < 2; i++)
            {
                await http.GetAsync(new Uri(dashboard.Url, "api/feed"), TestContext.Current.CancellationToken);
            }
        }
        finally
        {
            await dashboard.DisposeAsync();
        }

        var after = await SnapshotAsync(db);
        Assert.Equal(2, after.Ids.Count);
        Assert.Equal(before.Ids, after.Ids);
        Assert.Equal(before.LastHash, after.LastHash);
    }

    [Fact]
    public async Task Start_RootRedirectsToTheDashboard()
    {
        var db = await SeedAsync("SEC-01");

        await using var dashboard = await DashboardCommand.StartAsync(
            db, 0, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

        Assert.NotNull(dashboard);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var root = new Uri(dashboard.Url, "/");
        var resp = await http.GetAsync(root, TestContext.Current.CancellationToken);

        Assert.True((int)resp.StatusCode is >= 300 and < 400, $"expected a redirect, got {resp.StatusCode}");
        Assert.EndsWith("/ai-sentinel/", resp.Headers.Location?.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Start_CancelledToken_ThrowsAndReleasesTheFile()
    {
        var db = await SeedAsync("SEC-01");
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DashboardCommand.StartAsync(
            db, 0, new StringWriter(), new StringWriter(), cts.Token));

        File.Delete(db);
        Assert.False(File.Exists(db));
    }

    [Fact]
    public async Task Run_MissingFile_ExitsOne()
    {
        var exit = await DashboardCommand.RunAsync(
            Path.Combine(_dir, "missing.db"), 0, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
    }

    [Fact]
    public async Task Command_NoDbAndDefaultPathNotRooted_ExitsOneWithMessage()
    {
        var command = DashboardCommand.Build(() => "audit.db");
        var root = new System.CommandLine.RootCommand { command };
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await root.Parse(["dashboard"]).InvokeAsync(
            new System.CommandLine.InvocationConfiguration { Output = stdout, Error = stderr },
            TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Contains("--db", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Start_PrintsChainVerification()
    {
        var db = await SeedAsync("SEC-01", "HAL-08");
        var stdout = new StringWriter();

        await using var dashboard = await DashboardCommand.StartAsync(
            db, 0, stdout, new StringWriter(), TestContext.Current.CancellationToken);

        Assert.NotNull(dashboard);
        var text = stdout.ToString();
        Assert.Contains("intact", text, StringComparison.Ordinal);
        Assert.Contains("2 entries", text, StringComparison.Ordinal);
        Assert.Contains(dashboard.Url.ToString(), text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Start_PortInUse_ReturnsNullWithMessage()
    {
        var db = await SeedAsync("SEC-01");
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var stderr = new StringWriter();

            var dashboard = await DashboardCommand.StartAsync(
                db, port, new StringWriter(), stderr, TestContext.Current.CancellationToken);

            Assert.Null(dashboard);
            Assert.Contains(port.ToString(System.Globalization.CultureInfo.InvariantCulture), stderr.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task<string> SeedAsync(params string[] detectorIds)
    {
        var db = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        var ct = TestContext.Current.CancellationToken;
        foreach (var id in detectorIds)
        {
            await store.AppendAsync(new AuditEntry(
                Id: Guid.NewGuid().ToString("N"),
                Timestamp: DateTimeOffset.UtcNow,
                Hash: "",
                PreviousHash: null,
                Severity: Severity.High,
                DetectorId: id,
                Summary: "seeded " + id), ct);
        }
        return db;
    }

    private static async Task<(List<string> Ids, string? LastHash)> SnapshotAsync(string db)
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        var ids = new List<string>();
        string? lastHash = null;
        await foreach (var entry in store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), TestContext.Current.CancellationToken))
        {
            ids.Add(entry.Id);
            lastHash = entry.Hash;
        }
        ids.Sort(StringComparer.Ordinal);
        return (ids, lastHash);
    }
}
