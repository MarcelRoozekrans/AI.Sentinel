using System.Net;
using System.Net.Sockets;
using AI.Sentinel.Audit;
using AI.Sentinel.Cli;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

/// <summary>
/// The dashboard host must take nothing from appsettings files or environment variables: a Kestrel:Endpoints
/// section there would override the listener and bypass the --bind validation and the proxy-only gate.
/// The environment variable test touches process-global state, so this class runs alone.
/// </summary>
[Collection("NonParallel")]
public class DashboardHostIsolationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-isolation-" + Guid.NewGuid().ToString("N"));

    public DashboardHostIsolationTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    [Fact]
    public async Task BuiltHost_ReadsNoFileOrEnvironmentConfiguration()
    {
        var (app, store) = await BuildAsync();
        await using var _ = app;
        await using var __ = store;

        Assert.All(AllProviders((IConfigurationRoot)app.Configuration), provider =>
            Assert.True(
                provider is MemoryConfigurationProvider or ChainedConfigurationProvider,
                $"Unexpected configuration provider {provider.GetType().Name}."));
    }

    private static IEnumerable<IConfigurationProvider> AllProviders(IConfigurationRoot root)
    {
        foreach (var provider in root.Providers)
        {
            yield return provider;
            if (provider is ChainedConfigurationProvider chained)
            {
                foreach (var inner in AllProviders((IConfigurationRoot)chained.Configuration))
                {
                    yield return inner;
                }
            }
        }
    }

    [Fact]
    public async Task Start_IgnoresKestrelEndpointsFromTheEnvironment()
    {
        const string name = "Kestrel__Endpoints__Evil__Url";
        var evilPort = FreePort();
        Environment.SetEnvironmentVariable(name, $"http://127.0.0.1:{evilPort}");
        try
        {
            var db = await SeedAsync();
            await using var dashboard = await DashboardCommand.StartAsync(
                db, 0, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

            Assert.NotNull(dashboard);
            using var http = new HttpClient();
            var resp = await http.GetAsync(new Uri(dashboard.Url, "api/stats"), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            using var probe = new TcpClient();
            await Assert.ThrowsAsync<SocketException>(async () =>
                await probe.ConnectAsync(IPAddress.Loopback, evilPort, TestContext.Current.CancellationToken));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private async Task<(WebApplication App, SqliteAuditStore Store)> BuildAsync()
    {
        var db = await SeedAsync();
        var settings = new DashboardSettings(db, 0);
        var plan = await DashboardApprovalPlan.LoadAsync(settings, new StringWriter());
        var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        return (DashboardCommand.BuildApp(store, settings, plan!), store);
    }

    private async Task<string> SeedAsync()
    {
        var db = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        await store.AppendAsync(new AuditEntry(
            Id: Guid.NewGuid().ToString("N"), Timestamp: DateTimeOffset.UtcNow, Hash: "", PreviousHash: null,
            Severity: Severity.High, DetectorId: "SEC-01", Summary: "seeded"), TestContext.Current.CancellationToken);
        return db;
    }
}
