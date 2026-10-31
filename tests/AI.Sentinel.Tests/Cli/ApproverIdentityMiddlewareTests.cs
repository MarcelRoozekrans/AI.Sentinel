using System.Net;
using AI.Sentinel.Cli;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

public class ApproverIdentityMiddlewareTests
{
    private const string DefaultHeader = "X-Auth-Request-User";

    private static DashboardSettings Settings(
        string[]? proxies = null, string header = DefaultHeader, bool local = false, string bind = "127.0.0.1") =>
        new("audit.db", 5000)
        {
            Bind = IPAddress.Parse(bind),
            TrustedProxies = (proxies ?? []).Select(IPNetwork.Parse).ToArray(),
            UserHeader = header,
            LocalApprover = local,
        };

    private static async Task<HttpClient> BuildClientAsync(
        DashboardSettings settings, string? remote, Action<HttpRequest>? prep = null)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .Configure(app =>
                {
                    app.Use(async (ctx, next) =>
                    {
                        ctx.Connection.RemoteIpAddress = remote is null ? null : IPAddress.Parse(remote);
                        prep?.Invoke(ctx.Request);
                        await next();
                    });
                    app.UseApproverIdentity(settings);
                    app.Run(ctx =>
                    {
                        var id = ctx.User.Identity;
                        return ctx.Response.WriteAsync(
                            $"{id?.IsAuthenticated == true}|{id?.Name}|{id?.AuthenticationType}");
                    });
                }))
            .StartAsync(TestContext.Current.CancellationToken);
        return host.GetTestClient();
    }

    private static async Task<(HttpStatusCode Status, string Body)> GetAsync(
        DashboardSettings settings, string? remote, Action<HttpRequest>? prep = null)
    {
        var client = await BuildClientAsync(settings, remote, prep);
        var res = await client.GetAsync("/", TestContext.Current.CancellationToken);
        return (res.StatusCode, await res.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static Action<HttpRequest> User(string value, string header = DefaultHeader) =>
        r => r.Headers[header] = value;

    [Fact]
    public async Task Proxy_InRange_WithHeader_IsAuthenticated()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.0.5", User("alice"));
        Assert.Equal("True|alice|TrustedProxy", body);
    }

    [Fact]
    public async Task Proxy_IPv4MappedRemote_IsInRange()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "::ffff:10.0.0.5", User("alice"));
        Assert.Equal("True|alice|TrustedProxy", body);
    }

    [Fact]
    public async Task Proxy_OutOfRange_WithHeader_IsAnonymous()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.1.5", User("alice"));
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task Proxy_NullRemote_IsAnonymous()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), null, User("alice"));
        Assert.Equal("False||", body);
    }

    public static TheoryData<string> BadHeaders() => new()
    {
        "",
        "   ",
        new string('a', 257),
        "ali\u0001ce",
    };

    [Theory]
    [MemberData(nameof(BadHeaders))]
    public async Task Proxy_InRange_BadHeader_IsAnonymous(string value)
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.0.5", User(value));
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task Proxy_InRange_MissingHeader_IsAnonymous()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.0.5");
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task Proxy_InRange_TwoValues_IsAnonymous()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.0.5",
            r => r.Headers[DefaultHeader] = new Microsoft.Extensions.Primitives.StringValues(["alice", "bob"]));
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task Proxy_MaxLengthHeader_IsAccepted()
    {
        var name = new string('a', 256);
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.0.5", User(name));
        Assert.Equal($"True|{name}|TrustedProxy", body);
    }

    [Fact]
    public async Task Proxy_CustomHeaderName_IsUsed()
    {
        var settings = Settings(["10.0.0.0/24"], header: "Remote-User");
        var (_, used) = await GetAsync(settings, "10.0.0.5", User("alice", "Remote-User"));
        var (_, ignored) = await GetAsync(settings, "10.0.0.5", User("alice"));
        Assert.Equal("True|alice|TrustedProxy", used);
        Assert.Equal("False||", ignored);
    }

    [Fact]
    public async Task Proxy_TrimsHeaderValue()
    {
        var (_, body) = await GetAsync(Settings(["10.0.0.0/24"]), "10.0.0.5", User("  alice "));
        Assert.Equal("True|alice|TrustedProxy", body);
    }

    [Fact]
    public async Task Local_Loopback_IsOsUser()
    {
        var (_, body) = await GetAsync(Settings(local: true), "127.0.0.1");
        Assert.Equal($"True|{Environment.UserName}|LocalApprover", body);
    }

    [Fact]
    public async Task Local_IPv6Loopback_IsOsUser()
    {
        var (_, body) = await GetAsync(Settings(local: true), "::1");
        Assert.Equal($"True|{Environment.UserName}|LocalApprover", body);
    }

    [Fact]
    public async Task Local_NonLoopback_IsAnonymous()
    {
        var (_, body) = await GetAsync(Settings(local: true), "192.0.2.7");
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task Local_IgnoresUserHeader()
    {
        var (_, body) = await GetAsync(Settings(local: true), "127.0.0.1", User("mallory"));
        Assert.Equal($"True|{Environment.UserName}|LocalApprover", body);
    }

    [Fact]
    public async Task NeitherMode_UserHeaderIgnored()
    {
        var (_, body) = await GetAsync(Settings(), "127.0.0.1", User("mallory"));
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task NonLoopbackBind_DirectClient_Is403()
    {
        var (status, body) = await GetAsync(Settings(["10.0.0.0/24"], bind: "0.0.0.0"), "192.0.2.7", User("alice"));
        Assert.Equal(HttpStatusCode.Forbidden, status);
        Assert.Equal("This dashboard only accepts requests through its trusted proxy.", body);
    }

    [Fact]
    public async Task NonLoopbackBind_NullRemote_Is403()
    {
        var (status, _) = await GetAsync(Settings(["10.0.0.0/24"], bind: "0.0.0.0"), null);
        Assert.Equal(HttpStatusCode.Forbidden, status);
    }

    [Fact]
    public async Task NonLoopbackBind_ProxyClient_PassesThrough()
    {
        var (status, body) = await GetAsync(Settings(["10.0.0.0/24"], bind: "0.0.0.0"), "::ffff:10.0.0.5", User("alice"));
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("True|alice|TrustedProxy", body);
    }

    [Fact]
    public async Task NonLoopbackBind_LoopbackClient_PassesThrough()
    {
        var (status, body) = await GetAsync(Settings(["10.0.0.0/24"], bind: "0.0.0.0"), "127.0.0.1");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("False||", body);
    }

    [Fact]
    public async Task LoopbackBind_NoGate()
    {
        var (status, _) = await GetAsync(Settings(["10.0.0.0/24"]), "192.0.2.7");
        Assert.Equal(HttpStatusCode.OK, status);
    }
}
