using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Tests.AspNetCore.PolicyFolder;
using AI.Sentinel.Tests.ClaudeCode.SignIn;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.AspNetCore.Events;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore.Events;

/// <summary>A host with the policy folder, the admin audit log and the events endpoints. The caller is whoever the X headers say.</summary>
internal sealed class ServerEventTestHost : IDisposable
{
    public const string Policy = "AISentinelEvents";

    public const string Nodes = """
        {
          "organisation": "acme",
          "nodes": [
            {"id": "acme", "kind": "organisation"},
            {"id": "team-a", "kind": "team", "settings": {"detailed_logging": true}},
            {"id": "team-b", "kind": "team"}
          ],
          "repositories": {"github.com/acme/widgets": "team-a", "github.com/acme/gadgets": "team-b"},
          "roles": [
            {"group": "sec", "role": "administrator", "node": "acme"},
            {"group": "leads-a", "role": "team_lead", "node": "team-a"},
            {"group": "leads-b", "role": "team_lead", "node": "team-b"}
          ]
        }
        """;

    public static readonly string Key = Convert.ToBase64String(new byte[32].Select((_, i) => (byte)(i + 1)).ToArray());

    private readonly PolicyFolderFixture _folder = new();

    private ServerEventTestHost(IHost host, ManualTime time)
    {
        Host = host;
        Time = time;
        Client = host.GetTestClient();
    }

    public IHost Host { get; }

    public ManualTime Time { get; }

    public HttpClient Client { get; }

    public IServerEventStore Store => Host.Services.GetRequiredService<IServerEventStore>();

    public static async Task<ServerEventTestHost> StartAsync(Action<ServerEventOptions>? configure = null)
    {
        var ct = TestContext.Current.CancellationToken;
        var folder = new PolicyFolderFixture();
        folder.Write("v1", nodes: Nodes);
        folder.LinkTo("v1");
        var time = new ManualTime();
        var seed = AI.Sentinel.Profiles.Ed25519Crypto.NewSeed();
        var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddSingleton<TimeProvider>(time);
                    s.AddAuthorization(o => o.AddPolicy(Policy, p => p.AddRequirements(new OrgRequirement())));
                    s.AddSingleton<IAuthorizationHandler, OrgHandler>();
                    s.AddSingleton<IReadOnlyList<AI.Sentinel.ClaudeCode.Policy.Rego.IRegoCompiler>>([folder.Compiler]);
                    s.AddAISentinelAdminAudit(o => o.SigningKey = Convert.ToBase64String(seed));
                    s.AddAISentinelPolicyFolder(o =>
                    {
                        o.Path = folder.Folder;
                        o.SigningKey = Convert.ToBase64String(seed);
                        o.SettleDelay = TimeSpan.FromMilliseconds(10);
                        o.PollInterval = TimeSpan.FromMilliseconds(100);
                    });
                    s.AddAISentinelServerEvents(o =>
                    {
                        o.PseudonymKey = Key;
                        o.MaxBatchBytes = 20_000;
                        configure?.Invoke(o);
                    });
                });
                web.Configure(app =>
                {
                    app.Use(SignInAs);
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapAISentinelServerEvents());
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
        var result = new ServerEventTestHost(host, time);
        result._folderOwner = folder;
        return result;
    }

    private PolicyFolderFixture? _folderOwner;

    public static HttpRequestMessage Post(string json, string? org, string? sub = "alice", string groups = "")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/ai-sentinel/events/ingest")
        {
            Content = new StringContent(json, Encoding.UTF8, new MediaTypeHeaderValue("application/json")),
        };
        return As(request, org, sub, groups);
    }

    public static HttpRequestMessage Get(string path, string? org, string? sub = "alice", string groups = "") =>
        As(new HttpRequestMessage(HttpMethod.Get, "/ai-sentinel/events/" + path), org, sub, groups);

    private static HttpRequestMessage As(HttpRequestMessage request, string? org, string? sub, string groups)
    {
        if (org is not null)
        {
            request.Headers.Add("X-Org", org);
        }

        if (sub is not null)
        {
            request.Headers.Add("X-Sub", sub);
        }

        if (groups.Length > 0)
        {
            request.Headers.Add("X-Groups", groups);
        }

        return request;
    }

    public static string Batch(string organisation, params string[] events) =>
        $$"""{"organisation":"{{organisation}}","events":[{{string.Join(',', events)}}]}""";

    public static string Event(string id, string outcome = "deny", string node = "team-a", string session = "s-1", string extra = "") =>
        $$"""{"event_id":"{{id}}","tool_kind":"shell","outcome":"{{outcome}}","node":"{{node}}","session":"{{session}}","policies":["p1"]{{extra}}}""";

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request) =>
        await Client.SendAsync(request, TestContext.Current.CancellationToken);

    public void Dispose()
    {
        Client.Dispose();
        Host.Dispose();
        _folderOwner?.Dispose();
    }

    private static async Task SignInAs(HttpContext ctx, Func<Task> next)
    {
        var claims = new List<Claim>();
        if (ctx.Request.Headers.TryGetValue("X-Org", out var org))
        {
            claims.Add(new Claim("org", org.ToString()));
        }

        if (ctx.Request.Headers.TryGetValue("X-Sub", out var sub))
        {
            claims.Add(new Claim("sub", sub.ToString()));
        }

        var groups = ctx.Request.Headers.TryGetValue("X-Groups", out var listed) ? listed.ToString() : string.Empty;
        claims.AddRange(groups.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(g => new Claim("groups", g)));
        // No headers means the request stays anonymous, as when the host's authentication finds no token.
        if (claims.Count > 0)
        {
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
