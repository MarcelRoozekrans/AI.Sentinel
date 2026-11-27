using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Tests.AspNetCore.PolicyFolder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore.SessionControl;

/// <summary>A test server with the policy server and the session control mapped. A caller is whoever the X-Org, X-User and X-Groups
/// headers say, as a validated token would.</summary>
internal sealed class SessionControlTestHost : IAsyncDisposable
{
    public const string Widgets = "github.com/acme/widgets";
    public const string Gadgets = "github.com/acme/gadgets";
    public const string Other = "github.com/acme/other";

    public const string Nodes = """
        {
          "organisation": "acme",
          "nodes": [
            {"id": "acme", "kind": "organisation"},
            {"id": "team-a", "kind": "team"},
            {"id": "team-b", "kind": "team"}
          ],
          "repositories": {"github.com/acme/widgets": "team-a", "github.com/acme/gadgets": "team-b", "github.com/acme/other": "acme"},
          "roles": [
            {"group": "sec", "role": "administrator", "node": "acme"},
            {"group": "leads-a", "role": "team_lead", "node": "team-a"},
            {"group": "leads-b", "role": "team_lead", "node": "team-b"}
          ]
        }
        """;

    private SessionControlTestHost(IHost host) => Host = host;

    public IHost Host { get; }

    public HttpClient Client => Host.GetTestClient();

    public HttpMessageHandler Handler => Host.GetTestServer().CreateHandler();

    public PolicyFolderLoader Loader => Host.Services.GetRequiredService<PolicyFolderLoader>();

    public static async Task<SessionControlTestHost> StartAsync(
        PolicyFolderFixture folder, byte[] seed, TimeSpan? heartbeat = null, IRegoCompiler? compiler = null, CancellationToken ct = default)
    {
        folder.Write("v1", nodes: Nodes);
        folder.LinkTo("v1");
        var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthorization(o => o.AddPolicy("AISentinelDeveloper", p => p.AddRequirements(new OrgRequirement())));
                    s.AddSingleton<IAuthorizationHandler, OrgHandler>();
                    s.AddSingleton<IReadOnlyList<IRegoCompiler>>([compiler ?? folder.Compiler]);
                    s.AddAISentinelAdminAudit(o => o.SigningKey = Convert.ToBase64String(seed));
                    s.AddSingleton<AI.Sentinel.AspNetCore.AdminAudit.IAdminAuditStore>(folder.Store);
                    s.AddAISentinelPolicyFolder(o =>
                    {
                        o.Path = folder.Folder;
                        o.SigningKey = Convert.ToBase64String(seed);
                        o.SettleDelay = TimeSpan.FromMilliseconds(10);
                        o.PollInterval = TimeSpan.FromMilliseconds(100);
                        o.SessionStreamHeartbeat = heartbeat ?? TimeSpan.FromSeconds(15);
                    });
                });
                web.Configure(app =>
                {
                    app.Use(SignInAs);
                    app.UseRouting();
                    app.UseEndpoints(e =>
                    {
                        e.MapAISentinelPolicyServer();
                        e.MapAISentinelSessionControl();
                    });
                });
            })
            .StartAsync(ct);
        var loader = host.Services.GetRequiredService<PolicyFolderLoader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (loader.Current is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, ct);
        }

        Assert.NotNull(loader.Current);
        return new SessionControlTestHost(host);
    }

    /// <summary>A request as <paramref name="user"/> of the groups would send it.</summary>
    public static HttpRequestMessage Request(HttpMethod method, string path, string? user = null, string groups = "", string? json = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (user is not null)
        {
            Sign(request, user, groups);
        }

        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
        }

        return request;
    }

    public static void Sign(HttpRequestMessage request, string user, string groups)
    {
        request.Headers.Add("X-Org", "acme");
        request.Headers.Add("X-User", user);
        request.Headers.Add("X-Groups", groups);
    }

    public static string PauseBody(string repository, string? reason = null, DateTimeOffset? until = null) =>
        System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["repository"] = repository,
            ["reason"] = reason,
            ["until"] = until,
        });

    public Task<HttpResponseMessage> PauseAsync(string session, string user, string groups, string repository, string? reason = null, CancellationToken ct = default) =>
        Client.SendAsync(Request(HttpMethod.Post, $"/ai-sentinel/sessions/{session}/pause", user, groups, PauseBody(repository, reason)), ct);

    public Task<HttpResponseMessage> ReleaseAsync(string session, string user, string groups, CancellationToken ct = default) =>
        Client.SendAsync(Request(HttpMethod.Post, $"/ai-sentinel/sessions/{session}/release", user, groups), ct);

    public async ValueTask DisposeAsync()
    {
        await Host.StopAsync();
        Host.Dispose();
    }

    private static async Task SignInAs(HttpContext ctx, Func<Task> next)
    {
        if (ctx.Request.Headers.TryGetValue("X-Org", out var org))
        {
            var claims = new List<Claim> { new("org", org.ToString()) };
            if (ctx.Request.Headers.TryGetValue("X-User", out var user))
            {
                claims.Add(new Claim("sub", user.ToString()));
            }

            if (ctx.Request.Headers.TryGetValue("X-Groups", out var groups))
            {
                claims.AddRange(groups.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries).Select(g => new Claim("groups", g)));
            }

            ctx.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        }

        await next();
    }

    private sealed class OrgRequirement : IAuthorizationRequirement;

    private sealed class OrgHandler : AuthorizationHandler<OrgRequirement, string>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OrgRequirement requirement, string organisation)
        {
            if (context.User.HasClaim("org", organisation))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
