using System.Net;
using System.Security.Claims;
using System.Text.Json;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.PolicyFolder.PolicyFolderFixture;

namespace AI.Sentinel.Tests.AspNetCore.PolicyFolder;

public sealed class ProfileServingTests : IDisposable
{
    private const string Policy = "AISentinelDeveloper";

    private readonly PolicyFolderFixture _folder = new();
    private readonly byte[] _seed = AI.Sentinel.Profiles.Ed25519Crypto.NewSeed();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _folder.Dispose();

    [Fact]
    public async Task The_keys_endpoint_answers_the_organisation_and_the_public_keys_in_the_form_the_sign_in_reads()
    {
        using var host = await StartAsync(publish: true);

        var response = await host.GetTestClient().SendAsync(Get(PolicyFolderExtensions.ProfileKeysPath, "acme"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var wire = JsonSerializer.Deserialize(await response.Content.ReadAsStringAsync(Ct), SignInJsonContext.Default.ProfileKeysWire)!;
        Assert.Equal("acme", wire.Organisation);
        var pinned = PinnedProfileKeys.FromBase64(wire.Keys!);
        Assert.Equal(1, pinned.Count);
        Assert.True(pinned.TryGet(new ProfileSigningKey(_seed).KeyId, out _));
        Assert.Equal(DeviceCodeSignIn.KeysPath, PolicyFolderExtensions.ProfileKeysPath);
    }

    [Fact]
    public async Task A_signed_in_developer_of_the_organisation_gets_a_profile_that_the_pinned_key_verifies()
    {
        using var host = await StartAsync(publish: true);
        var client = host.GetTestClient();
        var pinned = await PinnedAsync(client);

        var response = await client.SendAsync(Get($"/ai-sentinel/policy/profile?repository={Uri.EscapeDataString(Repository)}", "acme"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var signed = SignedProfile.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        var verification = ProfileVerifier.Verify(signed, pinned, "acme", Repository, DateTimeOffset.UtcNow);
        Assert.True(verification.IsAccepted, verification.Rejection.ToString());
        var profile = verification.Profile!;
        Assert.Equal(("acme", Repository, "team-a"), (profile.Organisation, profile.Repository, profile.Node));
        Assert.Equal("closed", profile.FailMode);
        Assert.Equal(TimeSpan.FromHours(24), profile.ExpiresAt - profile.IssuedAt);
        Assert.True(profile.LoggingSwitches["detailed"]);
        var published = host.Services.GetRequiredService<PolicyFolderLoader>().Current!;
        Assert.Equal(published.ModuleHash, profile.ModuleHash);
        Assert.Equal(published.Version, profile.ConfigurationVersion);
        Assert.Contains("recursive delete", profile.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_repository_of_the_organisation_node_gets_the_default_lifetime_of_seven_days()
    {
        using var host = await StartAsync(publish: true);
        var client = host.GetTestClient();

        var response = await client.SendAsync(Get("/ai-sentinel/policy/profile?repository=https%3A%2F%2Fgithub.com%2Facme%2Fother.git", "acme"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var profile = ProfileVerifier.Verify(SignedProfile.Parse(await response.Content.ReadAsStringAsync(Ct))!, await PinnedAsync(client),
            "acme", "https://github.com/acme/other.git", DateTimeOffset.UtcNow).Profile!;
        Assert.Equal("acme", profile.Node);
        Assert.Equal(TimeSpan.FromDays(7), profile.ExpiresAt - profile.IssuedAt);
    }

    [Fact]
    public async Task A_repository_no_node_owns_gets_no_profile()
    {
        using var host = await StartAsync(publish: true);

        var response = await host.GetTestClient().SendAsync(Get("/ai-sentinel/policy/profile?repository=github.com%2Felse%2Fwhere", "acme"), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task A_request_without_a_repository_is_refused()
    {
        using var host = await StartAsync(publish: true);

        var response = await host.GetTestClient().SendAsync(Get("/ai-sentinel/policy/profile", "acme"), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("/.well-known/ai-sentinel/profile-keys")]
    [InlineData("/ai-sentinel/policy/profile?repository=github.com%2Facme%2Fwidgets")]
    [InlineData("/ai-sentinel/policy/node-map")]
    public async Task Only_a_signed_in_developer_of_the_organisation_is_served(string path)
    {
        using var host = await StartAsync(publish: true);
        var client = host.GetTestClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get(path, null), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Get(path, "another-org"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get(path, "acme"), Ct)).StatusCode);
    }

    [Theory]
    [InlineData("/.well-known/ai-sentinel/profile-keys")]
    [InlineData("/ai-sentinel/policy/profile?repository=github.com%2Facme%2Fwidgets")]
    [InlineData("/ai-sentinel/policy/node-map")]
    public async Task Nothing_is_served_before_a_configuration_is_published(string path)
    {
        using var host = await StartAsync(publish: false);

        var response = await host.GetTestClient().SendAsync(Get(path, "acme"), Ct);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task The_node_map_gives_the_hooks_the_repository_to_node_map_they_cache()
    {
        using var host = await StartAsync(publish: true);

        var response = await host.GetTestClient().SendAsync(Get("/ai-sentinel/policy/node-map", "acme"), Ct);

        var map = JsonSerializer.Deserialize<Dictionary<string, string>>(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal("team-a", map["github.com/acme/widgets"]);
        Assert.Equal("acme", map["github.com/acme/other"]);
    }

    [Fact]
    public async Task No_endpoint_accepts_policy_or_node_configuration()
    {
        using var host = await StartAsync(publish: true);

        var endpoints = host.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();

        Assert.NotEmpty(endpoints);
        foreach (var endpoint in endpoints)
        {
            var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods;
            Assert.Equal(["GET"], methods);
        }

        var client = host.GetTestClient();
        foreach (var path in new[] { "/ai-sentinel/policy/profile?repository=github.com%2Facme%2Fwidgets", "/ai-sentinel/policy/node-map", "/ai-sentinel/policy", "/.well-known/ai-sentinel/profile-keys" })
        {
            foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete })
            {
                var request = Get(path, "acme");
                var send = new HttpRequestMessage(method, request.RequestUri) { Content = new StringContent("package sentinel") };
                send.Headers.Add("X-Org", "acme");
                var status = (await client.SendAsync(send, Ct)).StatusCode;
                Assert.True(status is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotFound, $"{method} {path} answered {status}");
            }
        }
    }

    [Fact]
    public async Task While_the_server_is_unreachable_a_hook_still_denies_a_call_that_matches_a_deny_rule_of_the_last_valid_profile()
    {
        var dir = ResidentTestSupport.NewDir();
        try
        {
            SignedProfile signed;
            PinnedProfileKeys pinned;
            using (var host = await StartAsync(publish: true, real: new ChildProcessCompiler()))
            {
                var client = host.GetTestClient();
                pinned = await PinnedAsync(client);
                var response = await client.SendAsync(Get($"/ai-sentinel/policy/profile?repository={Uri.EscapeDataString(Repository)}", "acme"), Ct);
                signed = SignedProfile.Parse(await response.Content.ReadAsStringAsync(Ct))!;
            }

            // The host is gone: this is the PC with the server unreachable, and only its state folder is left.
            var state = new ResidentState(ResidentPaths.Prepare(new ResidentSettings(dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));
            var now = DateTimeOffset.UtcNow;
            Assert.True(state.StoreProfile(signed, pinned, "acme", Repository, now).IsAccepted);
            var input = PolicyInputSerializer.Serialize(PolicyInputBuilder.Build(
                PolicyClis.ClaudeCode, "Bash",
                JsonDocument.Parse("{\"command\":\"rm -rf build\"}").RootElement, "s-1", [], "/work/repo"));

            var decision = ProfileDecider.Decide(state, pinned, "acme", Repository, now, input, RegoPolicyTestSupport.SharedCache,
                RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));

            Assert.Equal(DecisionOutcome.Deny, decision.Decision!.Outcome);
            Assert.Equal(["recursive delete"], decision.Decision.Reasons);
        }
        finally
        {
            ResidentTestSupport.Delete(dir);
        }
    }

    private HttpRequestMessage Get(string path, string? organisation)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (organisation is not null)
        {
            request.Headers.Add("X-Org", organisation);
        }

        return request;
    }

    private async Task<PinnedProfileKeys> PinnedAsync(HttpClient client)
    {
        var response = await client.SendAsync(Get(PolicyFolderExtensions.ProfileKeysPath, "acme"), Ct);
        var wire = JsonSerializer.Deserialize(await response.Content.ReadAsStringAsync(Ct), SignInJsonContext.Default.ProfileKeysWire)!;
        return PinnedProfileKeys.FromBase64(wire.Keys!);
    }

    private async Task<IHost> StartAsync(bool publish, IRegoCompiler? real = null)
    {
        if (publish)
        {
            _folder.Write("v1");
            _folder.LinkTo("v1");
        }

        var compilers = new List<IRegoCompiler> { real ?? _folder.Compiler };
        var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthorization(o => o.AddPolicy(Policy, p => p.AddRequirements(new OrgRequirement())));
                    s.AddSingleton<IAuthorizationHandler, OrgHandler>();
                    s.AddSingleton<IReadOnlyList<IRegoCompiler>>(compilers);
                    s.AddAISentinelAdminAudit(o => o.SigningKey = Convert.ToBase64String(_seed));
                    s.AddAISentinelPolicyFolder(o =>
                    {
                        o.Path = _folder.Folder;
                        o.SigningKey = Convert.ToBase64String(_seed);
                        o.PolicyName = Policy;
                        o.SettleDelay = TimeSpan.FromMilliseconds(10);
                        o.PollInterval = TimeSpan.FromMilliseconds(100);
                    });
                });
                web.Configure(app =>
                {
                    app.Use(async (ctx, next) =>
                    {
                        if (ctx.Request.Headers.TryGetValue("X-Org", out var org))
                        {
                            ctx.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("org", org.ToString())], "test"));
                        }

                        await next(ctx);
                    });
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapAISentinelPolicyServer());
                });
            })
            .StartAsync(Ct);
        var loader = host.Services.GetRequiredService<PolicyFolderLoader>();
        if (publish)
        {
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (loader.Current is null && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20, Ct);
            }

            Assert.NotNull(loader.Current);
        }

        return host;
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
