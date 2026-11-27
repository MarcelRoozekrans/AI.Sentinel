using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ServerSample;
using AI.Sentinel.Tests.AspNetCore.PolicyFolder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Samples;

/// <summary>Drives the standalone server sample, the one the docs page describes, through approve, deny, pause and release over its
/// HTTP API, with no central product around it (#666).</summary>
public sealed class StandaloneServerSampleTests
{
    private const string Widgets = "github.com/acme/widgets";

    [Fact]
    public async Task Sample_ApprovesDeniesPausesAndReleasesOverHttp()
    {
        var ct = TestContext.Current.CancellationToken;
        using var folder = new PolicyFolderFixture();
        folder.Write("v1");
        folder.LinkTo("v1");
        var app = BuildSample(folder);
        await app.StartAsync(ct);
        try
        {
            await WaitForPolicyAsync(app, ct);
            var client = app.GetTestClient();

            var store = app.Services.GetRequiredService<IApprovalStore>();
            var toApprove = await PendingAsync(store, "alice", ct);
            var toDeny = await PendingAsync(store, "carol", ct);

            Assert.Equal(HttpStatusCode.OK, (await SendAsync(client, HttpMethod.Post, $"/ai-sentinel/api/approvals/{toApprove}/approve", "ops-bob", "", ct: ct)).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await SendAsync(client, HttpMethod.Post, $"/ai-sentinel/api/approvals/{toDeny}/deny", "ops-bob", "", ct: ct)).StatusCode);

            var pause = await SendAsync(client, HttpMethod.Post, "/ai-sentinel/sessions/s-1/pause", "lead-dan", "leads",
                $$"""{"repository": "{{Widgets}}", "reason": "check the last commands"}""", ct);
            Assert.Equal(HttpStatusCode.OK, pause.StatusCode);
            var listed = await (await SendAsync(client, HttpMethod.Get, "/ai-sentinel/sessions", "lead-dan", "leads", ct: ct)).Content.ReadAsStringAsync(ct);
            Assert.Contains("s-1", listed, StringComparison.Ordinal);
            Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(client, HttpMethod.Post, "/ai-sentinel/sessions/s-1/release", "lead-dan", "leads", ct: ct)).StatusCode);

            var export = await SendAsync(client, HttpMethod.Get, "/ai-sentinel/admin-audit/acme/export", "sec-eve", "sec", ct: ct);
            Assert.Equal(HttpStatusCode.OK, export.StatusCode);
            using var doc = JsonDocument.Parse(await export.Content.ReadAsStringAsync(ct));
            var actions = doc.RootElement.GetProperty("entries").EnumerateArray()
                .Select(e => e.GetProperty("action").GetString()).ToHashSet(StringComparer.Ordinal);
            Assert.Superset(new HashSet<string?>(StringComparer.Ordinal) { "approve", "deny", "pause", "release" }, actions);

            Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(client, HttpMethod.Get, "/ai-sentinel/sessions", user: null, ct: ct)).StatusCode);
        }
        finally
        {
            await app.StopAsync(ct);
            await app.DisposeAsync();
        }
    }

    private static WebApplication BuildSample(PolicyFolderFixture folder)
    {
        // The default host watches appsettings.json for changes. Every inotify instance of the user is spoken for on a busy
        // machine, so the host watches by polling, which is what DOTNET_USE_POLLING_FILE_WATCHER is for. The host reads it at build.
        Environment.SetEnvironmentVariable("DOTNET_USE_POLLING_FILE_WATCHER", "true");
        var seed = Convert.ToBase64String(new byte[32].Select((_, i) => (byte)(i + 1)).ToArray());
        return ServerSampleApp.Build(
            [$"--Sentinel:SigningKey={seed}", $"--Sentinel:PolicyPath={folder.Folder}", "--Sentinel:Organisation=acme"],
            builder =>
            {
                builder.WebHost.UseTestServer();
                builder.Logging.ClearProviders();
                // A token from an identity provider is replaced by headers, and opa by a scripted compiler.
                builder.Services.AddAuthentication("Headers").AddScheme<AuthenticationSchemeOptions, HeaderAuthentication>("Headers", null);
                builder.Services.AddSingleton<IReadOnlyList<IRegoCompiler>>([folder.Compiler]);
                builder.Services.Configure<PolicyFolderOptions>(o =>
                {
                    o.SettleDelay = TimeSpan.FromMilliseconds(10);
                    o.PollInterval = TimeSpan.FromMilliseconds(100);
                });
            });
    }

    private static async Task WaitForPolicyAsync(WebApplication app, CancellationToken ct)
    {
        var loader = app.Services.GetRequiredService<PolicyFolderLoader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (loader.Current is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, ct);
        }

        Assert.NotNull(loader.Current);
    }

    private static async Task<string> PendingAsync(IApprovalStore store, string caller, CancellationToken ct) =>
        ((ApprovalState.Pending)await store.EnsureRequestAsync(
            new Caller(caller), new ApprovalSpec { PolicyName = "p" }, new ApprovalContext("delete_database", default, null), ct)).RequestId;

    private static Task<HttpResponseMessage> SendAsync(
        HttpClient client, HttpMethod method, string path, string? user, string groups = "", string? body = null, CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(method, path);
        if (user is not null)
        {
            request.Headers.Add("X-User", user);
            request.Headers.Add("X-Groups", groups);
        }

        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return client.SendAsync(request, ct);
    }

    private sealed record Caller(string Id) : ISecurityContext
    {
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);

        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    /// <summary>Stands in for a validated token: the user and groups come from headers, as the sub and groups claims would.</summary>
    private sealed class HeaderAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("X-User", out var user))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims = new List<Claim> { new("sub", user.ToString()) };
            claims.AddRange(Request.Headers["X-Groups"].ToString().Split(',', StringSplitOptions.RemoveEmptyEntries).Select(g => new Claim("groups", g)));
            var identity = new ClaimsIdentity(claims, Scheme.Name, "sub", ClaimTypes.Role);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }
    }
}
