using System.CommandLine;
using System.Net;
using System.Net.Sockets;
using AI.Sentinel.Cli;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

public class DashboardOptionsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-dashopts-" + Guid.NewGuid().ToString("N"));

    public DashboardOptionsTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    private RootCommand Root(string? env = null) =>
        new() { DashboardCommand.Build(() => Path.Combine(_dir, "audit.db"), () => env) };

    private DashboardSettings Read(string? env, params string[] args)
    {
        var root = new RootCommand { DashboardCommand.Build(() => Path.Combine(_dir, "audit.db"), () => env, out var read) };
        return read(root.Parse(["dashboard", .. args]));
    }

    private async Task<(int Exit, string Err)> InvokeAsync(params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await Root().Parse(["dashboard", .. args]).InvokeAsync(
            new InvocationConfiguration { Output = stdout, Error = stderr }, TestContext.Current.CancellationToken);
        return (exit, stderr.ToString());
    }

    private static void AssertRefused((int Exit, string Err) r, string expected)
    {
        Assert.Equal(1, r.Exit);
        Assert.Contains(expected, r.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("   at ", r.Err, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("192.168.1.10")]
    public async Task NonLoopbackBind_WithoutTrustedProxy_IsRefused(string bind) =>
        AssertRefused(await InvokeAsync("--bind", bind), "--trusted-proxy");

    [Fact]
    public async Task Bind_NotAnIp_IsRefused() =>
        AssertRefused(await InvokeAsync("--bind", "localhost"), "--bind");

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("abc")]
    public async Task TrustedProxy_NotACidr_IsRefused(string cidr) =>
        AssertRefused(await InvokeAsync("--trusted-proxy", cidr), "--trusted-proxy");

    [Fact]
    public async Task UserHeader_WithoutTrustedProxy_IsRefused() =>
        AssertRefused(await InvokeAsync("--user-header", "X-User"), "--trusted-proxy");

    [Fact]
    public async Task UserHeader_InvalidToken_IsRefused() =>
        AssertRefused(await InvokeAsync("--trusted-proxy", "10.0.0.1", "--user-header", "X Auth"), "--user-header");

    [Fact]
    public async Task LocalApprover_WithTrustedProxy_IsRefused() =>
        AssertRefused(await InvokeAsync("--local-approver", "--trusted-proxy", "10.0.0.1"), "--local-approver");

    [Fact]
    public async Task LocalApprover_WithNonLoopbackBind_IsRefused() =>
        AssertRefused(await InvokeAsync("--local-approver", "--bind", "0.0.0.0"), "--local-approver needs a loopback --bind");

    [Fact]
    public async Task Bind_WithScopeId_IsRefused() =>
        AssertRefused(await InvokeAsync("--bind", "fe80::1%1"), "scope ids");

    [Theory]
    [InlineData("::1")]
    [InlineData("127.0.0.1")]
    public void ValidLoopbackBind_IsAccepted(string value) =>
        Assert.Empty(Root().Parse(["dashboard", "--bind", value]).Errors);

    [Theory]
    [InlineData("0.0.0.0", "http://127.0.0.1:5170/ai-sentinel/")]
    [InlineData("::", "http://[::1]:5170/ai-sentinel/")]
    [InlineData("10.1.2.3", "http://10.1.2.3:5170/ai-sentinel/")]
    [InlineData("127.0.0.1", "http://127.0.0.1:5170/ai-sentinel/")]
    public void BrowsableUrl_MapsAWildcardBindToLoopback(string bind, string expected) =>
        Assert.Equal(expected, DashboardCommand.BrowsableUrl(new Uri("http://0.0.0.0:5170"), IPAddress.Parse(bind)).AbsoluteUri);

    [Fact]
    public void WildcardBind_WithTrustedProxy_IsAccepted() =>
        Assert.Empty(Root().Parse(["dashboard", "--bind", "0.0.0.0", "--trusted-proxy", "10.0.0.0/8"]).Errors);

    [Fact]
    public void UserHeader_WithTrustedProxy_IsAccepted() =>
        Assert.Empty(Root().Parse(["dashboard", "--trusted-proxy", "10.0.0.1", "--user-header", "Remote-User"]).Errors);

    [Fact]
    public void Settings_ExplicitBind_IsRead()
    {
        var s = Read(null, "--bind", "0.0.0.0", "--trusted-proxy", "10.0.0.0/8", "--user-header", "Remote-User");
        Assert.Equal(IPAddress.Any, s.Bind);
        Assert.Equal("Remote-User", s.UserHeader);
    }

    [Theory]
    [InlineData("::ffff:10.0.0.1", "10.0.0.1/32")]
    [InlineData("::ffff:10.0.0.0/104", "10.0.0.0/8")]
    public void Settings_MappedProxy_IsNormalisedToIPv4(string input, string expected)
    {
        var s = Read(null, "--trusted-proxy", input);
        Assert.Equal(expected, Assert.Single(s.TrustedProxies).ToString());
    }

    [Fact]
    public void Settings_Defaults()
    {
        var s = Read(null);
        Assert.Equal(IPAddress.Loopback, s.Bind);
        Assert.Equal("X-Auth-Request-User", s.UserHeader);
        Assert.Empty(s.TrustedProxies);
        Assert.Null(s.ApprovalConfigPath);
        Assert.False(s.ApprovalConfigExplicit);
        Assert.False(s.LocalApprover);
    }

    [Fact]
    public void Settings_ApprovalConfigFlagWinsOverEnvironment()
    {
        var s = Read("/env/cfg.json", "--approval-config", "/flag/cfg.json");
        Assert.Equal("/flag/cfg.json", s.ApprovalConfigPath);
        Assert.True(s.ApprovalConfigExplicit);
    }

    [Fact]
    public void Settings_ApprovalConfigFromEnvironment()
    {
        var s = Read("/env/cfg.json");
        Assert.Equal("/env/cfg.json", s.ApprovalConfigPath);
        Assert.False(s.ApprovalConfigExplicit);
    }

    [Fact]
    public void Settings_BlankEnvironment_IsNoConfig()
    {
        var s = Read("   ");
        Assert.Null(s.ApprovalConfigPath);
        Assert.False(s.ApprovalConfigExplicit);
    }

    [Theory]
    [InlineData("10.1.2.3", "10.1.2.3/32")]
    [InlineData("::1", "::1/128")]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    public void Settings_BareProxyAddress_IsSingleHost(string input, string expected)
    {
        var s = Read(null, "--trusted-proxy", input);
        Assert.Equal(expected, Assert.Single(s.TrustedProxies).ToString());
    }

    [Fact]
    public void Settings_TrustedProxy_IsRepeatable()
    {
        var s = Read(null, "--trusted-proxy", "10.0.0.1", "--trusted-proxy", "192.168.0.0/16");
        Assert.Equal(2, s.TrustedProxies.Count);
    }

    private static bool Ipv6LoopbackAvailable()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return false;
        }
        try
        {
            using var probe = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private async Task<string> SeedAsync()
    {
        var db = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        await using var store = new AI.Sentinel.Sqlite.SqliteAuditStore(
            new AI.Sentinel.Sqlite.SqliteAuditStoreOptions { DatabasePath = db });
        await store.AppendAsync(new AI.Sentinel.Audit.AuditEntry(
            Id: "id1", Timestamp: DateTimeOffset.UtcNow, Hash: "", PreviousHash: null,
            Severity: AI.Sentinel.Detection.Severity.High, DetectorId: "SEC-01", Summary: "seeded"),
            TestContext.Current.CancellationToken);
        return db;
    }

    [Fact]
    public async Task Start_BindsTheGivenLoopbackAddress()
    {
        if (!Ipv6LoopbackAvailable())
        {
            Assert.Skip("IPv6 loopback is unavailable.");
        }
        var db = await SeedAsync();

        var dashboard = await DashboardCommand.StartAsync(
            new DashboardSettings(db, 0) { Bind = IPAddress.IPv6Loopback },
            new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

        Assert.NotNull(dashboard);
        await using (dashboard)
        {
            Assert.Equal("[::1]", dashboard.Url.Host);
            using var http = new HttpClient();
            var resp = await http.GetAsync(new Uri(dashboard.Url, "api/stats"), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
    }
}
