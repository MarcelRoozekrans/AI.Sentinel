using System.Net;
using System.Security.Claims;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.Profiles;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.PolicyFolder.PolicyFolderFixture;

namespace AI.Sentinel.Tests.AspNetCore.PolicyFolder;

public sealed class NodeRoleTests : IDisposable
{
    private const string Other = "github.com/acme/other";

    private const string TwoTeams = """
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

    private const string Gadgets = "github.com/acme/gadgets";

    private readonly PolicyFolderFixture _folder = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _folder.Dispose();

    private static ClaimsPrincipal User(string subject, params string[] groups) =>
        new(new ClaimsIdentity(
            [new Claim("sub", subject), .. groups.Select(g => new Claim("groups", g))], "test"));

    private async Task<NodeRoles> RolesAsync(PolicyFolderOptions? options = null, string nodes = TwoTeams)
    {
        _folder.Write("v1", nodes: nodes);
        _folder.LinkTo("v1");
        await _folder.Loader.ReloadAsync(Ct);
        return new NodeRoles(_folder.Loader, Options.Create(options ?? new PolicyFolderOptions()));
    }

    [Fact]
    public async Task The_developer_is_the_subject_claim_and_the_groups_are_the_groups_claim_of_the_validated_token()
    {
        var roles = await RolesAsync();
        var user = User("alice", "leads-a", "everyone");

        Assert.Equal("alice", roles.DeveloperOf(user));
        Assert.Equal(["everyone", "leads-a"], roles.GroupsOf(user).Order(StringComparer.Ordinal), StringComparer.Ordinal);
    }

    [Fact]
    public async Task Both_claim_names_are_settings_and_the_inbound_mapped_subject_is_read_too()
    {
        var options = new PolicyFolderOptions { DeveloperClaim = "preferred_username", GroupsClaim = "roles" };
        var roles = await RolesAsync(options);
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("preferred_username", "bob"), new Claim("roles", "[\"sec\",\"x\"]"), new Claim("groups", "leads-a")], "test"));

        Assert.Equal("bob", roles.DeveloperOf(user));
        Assert.Equal(["sec", "x"], roles.GroupsOf(user).Order(StringComparer.Ordinal), StringComparer.Ordinal);

        var mapped = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "carol")], "test"));
        Assert.Equal("carol", (await RolesAsync_Default()).DeveloperOf(mapped));
    }

    private Task<NodeRoles> RolesAsync_Default() => Task.FromResult(new NodeRoles(_folder.Loader, Options.Create(new PolicyFolderOptions())));

    [Theory]
    [InlineData(null, null, "sub", "groups")]
    [InlineData("preferred_username", "idp_groups", "preferred_username", "idp_groups")]
    public async Task The_developer_and_the_groups_are_mapped_from_a_token_the_authentication_handler_validated(
        string? developerClaim, string? groupsClaim, string developerName, string groupsName)
    {
        var key = new SymmetricSecurityKey(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>(StringComparer.Ordinal) { [developerName] = "lena", [groupsName] = new[] { "leads-a", "everyone" } },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        });
        _folder.Write("v1", nodes: TwoTeams);
        _folder.LinkTo("v1");
        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
                        o.TokenValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = key,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        });
                    s.AddAuthorization();
                    s.AddSingleton<IReadOnlyList<AI.Sentinel.ClaudeCode.Policy.Rego.IRegoCompiler>>([_folder.Compiler]);
                    var seed = Convert.ToBase64String(Ed25519Crypto.NewSeed());
                    s.AddAISentinelAdminAudit(o => o.SigningKey = seed);
                    s.AddAISentinelPolicyFolder(o =>
                    {
                        o.Path = _folder.Folder;
                        o.SigningKey = seed;
                        if (developerClaim is not null) { o.DeveloperClaim = developerClaim; }
                        if (groupsClaim is not null) { o.GroupsClaim = groupsClaim; }
                    });
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(e => e.MapGet("/who", (HttpContext http, NodeRoles roles) =>
                        $"{roles.DeveloperOf(http.User)}|{string.Join(',', roles.GroupsOf(http.User).Order(StringComparer.Ordinal))}"
                        + $"|{roles.RoleOn(http.User, "team-a")}|{roles.RoleOn(http.User, "team-b")}"));
                });
            })
            .StartAsync(Ct);
        var loader = host.Services.GetRequiredService<PolicyFolderLoader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (loader.Current is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, Ct);
        }

        var request = new HttpRequestMessage(HttpMethod.Get, "/who");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var response = await host.GetTestClient().SendAsync(request, Ct);

        Assert.Equal("lena|everyone,leads-a|TeamLead|Developer", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task An_administrator_of_the_organisation_holds_the_role_on_every_node()
    {
        var roles = await RolesAsync();
        var admin = User("root", "sec");

        Assert.All(["acme", "team-a", "team-b"], node => Assert.Equal(NodeRole.Administrator, roles.RoleOn(admin, node)));
        Assert.True(roles.AllowsOnSession(admin, NodeRole.Administrator, Repository));
        Assert.True(roles.AllowsOnSession(admin, NodeRole.TeamLead, Gadgets));
    }

    [Fact]
    public async Task A_team_lead_holds_the_role_on_their_team_only_and_everyone_else_is_a_developer()
    {
        var roles = await RolesAsync();
        var lead = User("lena", "leads-a");

        Assert.Equal(NodeRole.TeamLead, roles.RoleOn(lead, "team-a"));
        Assert.Equal(NodeRole.Developer, roles.RoleOn(lead, "team-b"));
        Assert.Equal(NodeRole.Developer, roles.RoleOn(lead, "acme"));
        Assert.Equal(NodeRole.Developer, roles.RoleOn(User("dev", "nobody"), "team-a"));
        Assert.Equal(NodeRole.Developer, roles.RoleOn(lead, "no-such-node"));
    }

    [Fact]
    public async Task A_team_lead_of_one_team_is_refused_on_the_sessions_of_another_team()
    {
        var roles = await RolesAsync();
        var lead = User("lena", "leads-a");

        Assert.True(roles.AllowsOnSession(lead, NodeRole.TeamLead, Repository));
        Assert.False(roles.AllowsOnSession(lead, NodeRole.TeamLead, Gadgets));
        Assert.False(roles.AllowsOnSession(lead, NodeRole.TeamLead, Other));
        Assert.False(roles.AllowsOnSession(lead, NodeRole.TeamLead, "github.com/else/where"));
        Assert.False(roles.AllowsOnSession(lead, NodeRole.Administrator, Repository));
    }

    [Fact]
    public async Task A_repository_that_no_node_owns_is_open_to_an_administrator_only()
    {
        var roles = await RolesAsync();

        Assert.True(roles.AllowsOnSession(User("root", "sec"), NodeRole.TeamLead, "github.com/else/where"));
        Assert.False(roles.AllowsOnSession(User("lena", "leads-a"), NodeRole.TeamLead, "github.com/else/where"));
    }

    [Fact]
    public async Task A_developer_sees_their_own_decisions_and_a_team_lead_those_of_their_team()
    {
        var roles = await RolesAsync();
        var dev = User("dave", "nobody");

        Assert.True(roles.MaySeeDecision(dev, Repository, "dave"));
        Assert.False(roles.MaySeeDecision(dev, Repository, "erin"));
        Assert.True(roles.MaySeeDecision(User("lena", "leads-a"), Repository, "erin"));
        Assert.False(roles.MaySeeDecision(User("lena", "leads-a"), Gadgets, "erin"));
        Assert.True(roles.MaySeeDecision(User("root", "sec"), Gadgets, "erin"));
    }

    [Fact]
    public async Task A_decision_on_a_repository_that_no_node_owns_is_open_to_an_administrator_only_even_for_its_requester()
    {
        var roles = await RolesAsync();
        const string Unowned = "github.com/else/where";

        Assert.False(roles.MaySeeDecision(User("dave", "nobody"), Unowned, "dave"));
        Assert.False(roles.MaySeeDecision(User("lena", "leads-a"), Unowned, "lena"));
        Assert.True(roles.MaySeeDecision(User("root", "sec"), Unowned, "dave"));
    }

    [Fact]
    public async Task A_developer_may_not_decide_and_nobody_decides_their_own_request()
    {
        var roles = await RolesAsync();

        Assert.False(roles.MayDecide(User("dave", "nobody"), Repository, "erin"));
        Assert.True(roles.MayDecide(User("lena", "leads-a"), Repository, "erin"));
        Assert.False(roles.MayDecide(User("lena", "leads-a"), Repository, "lena"));
        Assert.False(roles.MayDecide(User("root", "sec"), Repository, "root"));
        Assert.True(roles.MayDecide(User("root", "sec"), Repository, "erin"));
        Assert.False(roles.MayDecide(User("lena", "leads-a"), Gadgets, "erin"));
        Assert.False(roles.MayDecide(new ClaimsPrincipal(new ClaimsIdentity([new Claim("groups", "sec")], "test")), Repository, "erin"));
    }

    [Fact]
    public async Task A_change_of_the_folder_changes_the_bindings_without_a_restart()
    {
        var roles = await RolesAsync();
        var lead = User("lena", "leads-a");
        Assert.True(roles.AllowsOnSession(lead, NodeRole.TeamLead, Repository));

        _folder.Write("v2", nodes: TwoTeams.Replace("\"leads-a\"", "\"someone-else\"", StringComparison.Ordinal));
        _folder.LinkTo("v2");
        await _folder.Loader.ReloadAsync(Ct);

        Assert.False(roles.AllowsOnSession(lead, NodeRole.TeamLead, Repository));
        Assert.True(roles.AllowsOnSession(User("sam", "someone-else"), NodeRole.TeamLead, Repository));
    }

    [Fact]
    public void Nothing_is_allowed_before_a_configuration_has_been_published()
    {
        var roles = new NodeRoles(_folder.Loader, Options.Create(new PolicyFolderOptions()));

        Assert.Equal(NodeRole.Developer, roles.RoleOn(User("root", "sec"), "acme"));
        Assert.False(roles.AllowsOnSession(User("root", "sec"), NodeRole.TeamLead, Repository));
        Assert.False(roles.IsAdministratorOf(User("root", "sec"), "acme"));
        Assert.False(roles.MaySeeDecision(User("dave", "nobody"), Repository, "dave"));
    }

    [Fact]
    public async Task An_administrator_is_one_of_the_organisation_the_published_configuration_names_and_of_no_other()
    {
        var roles = await RolesAsync();

        Assert.True(roles.IsAdministratorOf(User("root", "sec"), "acme"));
        Assert.False(roles.IsAdministratorOf(User("root", "sec"), "globex"));
        Assert.False(roles.IsAdministratorOf(User("lead", "leads-a"), "acme"));
    }

    [Theory]
    [InlineData("[not json")]
    [InlineData("[\"sec\"")]
    public async Task A_groups_claim_that_starts_like_an_array_but_is_not_one_is_one_group_name(string value)
    {
        var roles = await RolesAsync();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "eve"), new Claim("groups", value)], "test"));

        Assert.Equal([value], roles.GroupsOf(user), StringComparer.Ordinal);
        Assert.False(roles.IsAdministratorOf(user, "acme"));
    }

    [Fact]
    public async Task The_requirement_goes_through_the_host_authorization_for_a_node()
    {
        var roles = await RolesAsync();
        using var provider = new ServiceCollection()
            .AddLogging().AddAuthorization()
            .AddSingleton(roles)
            .AddSingleton<IAuthorizationHandler, NodeRoleHandler>()
            .BuildServiceProvider();
        var authorization = provider.GetRequiredService<IAuthorizationService>();
        var lead = User("lena", "leads-a");

        Assert.True((await authorization.AuthorizeAsync(lead, "team-a", new NodeRoleRequirement(NodeRole.TeamLead))).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(lead, "team-b", new NodeRoleRequirement(NodeRole.TeamLead))).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(lead, "acme", new NodeRoleRequirement(NodeRole.Administrator))).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(User("root", "sec"), "acme", new NodeRoleRequirement(NodeRole.Administrator))).Succeeded);
    }

    [Fact]
    public async Task The_audit_export_needs_the_administrator_role_on_top_of_the_host_policy()
    {
        using var host = await StartAuditHostAsync();
        var client = host.GetTestClient();

        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Export("sec"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Export("leads-a"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Export("nobody"), Ct)).StatusCode);
    }

    private static HttpRequestMessage Export(string group)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/ai-sentinel/admin-audit/acme/export");
        request.Headers.Add("X-Group", group);
        return request;
    }

    private async Task<IHost> StartAuditHostAsync()
    {
        var seed = Ed25519Crypto.NewSeed();
        _folder.Write("v1", nodes: TwoTeams);
        _folder.LinkTo("v1");
        var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthorization(o => o.AddPolicy("AISentinelAdminAudit", p => p.RequireAssertion(_ => true)));
                    s.AddSingleton<IReadOnlyList<AI.Sentinel.ClaudeCode.Policy.Rego.IRegoCompiler>>([_folder.Compiler]);
                    s.AddAISentinelAdminAudit(o => o.SigningKey = Convert.ToBase64String(seed));
                    s.AddAISentinelPolicyFolder(o =>
                    {
                        o.Path = _folder.Folder;
                        o.SigningKey = Convert.ToBase64String(seed);
                        o.SettleDelay = TimeSpan.FromMilliseconds(10);
                        o.PollInterval = TimeSpan.FromMilliseconds(100);
                    });
                });
                web.Configure(app =>
                {
                    app.Use(async (ctx, next) =>
                    {
                        if (ctx.Request.Headers.TryGetValue("X-Group", out var group))
                        {
                            ctx.User = User("someone", group.ToString());
                        }

                        await next();
                    });
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapAISentinelAdminAudit());
                });
            })
            .StartAsync(Ct);
        var loader = host.Services.GetRequiredService<PolicyFolderLoader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (loader.Current is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, Ct);
        }

        Assert.NotNull(loader.Current);
        return host;
    }
}
