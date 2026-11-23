using System.Net;
using System.Security.Claims;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.Profiles;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.AdminAuditTestSupport;

namespace AI.Sentinel.Tests.AspNetCore;

public sealed class AdminAuditLogTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("Approve", "approve")]
    [InlineData("Deny", "deny")]
    [InlineData("Pause", "pause")]
    [InlineData("Release", "release")]
    [InlineData("Publish", "publish")]
    [InlineData("RejectedPublish", "rejected_publish")]
    [InlineData("Rollback", "rollback")]
    public async Task Entry_RecordsActionActorTimeTargetAndChannel(string actionName, string wire)
    {
        var action = Enum.Parse<AdminAuditAction>(actionName);
        await RecordsAction(action, wire);
    }

    private static async Task RecordsAction(AdminAuditAction action, string wire)
    {
        var time = new SettableTime(T0);
        var log = NewLog(NewKey(), time);

        var entry = await log.RecordAsync("org-a", action, "alice", "request-1", AdminAuditChannel.Mcp, Ct);

        Assert.Equal(wire, entry.Action);
        Assert.Equal("alice", entry.Actor);
        Assert.Equal("request-1", entry.Target);
        Assert.Equal("mcp", entry.Channel);
        Assert.Equal(T0, entry.Timestamp);
        Assert.Equal("org-a", entry.Organisation);
    }

    [Theory]
    [InlineData("Web", "web")]
    [InlineData("Mcp", "mcp")]
    [InlineData("Git", "git")]
    public async Task Entry_RecordsEachChannel(string channelName, string wire)
    {
        var channel = Enum.Parse<AdminAuditChannel>(channelName);
        var log = NewLog(NewKey(), new SettableTime(T0));
        var entry = await log.RecordAsync("org-a", AdminAuditAction.Publish, "bot", "config-7", channel, Ct);
        Assert.Equal(wire, entry.Channel);
    }

    [Fact]
    public async Task Entries_AreHashChainedPerOrganisation()
    {
        var store = new InMemoryAdminAuditStore();
        var log = NewLog(NewKey(), new SettableTime(T0), store);
        await SeedAsync(log, "org-a", 3, Ct);
        await SeedAsync(log, "org-b", 2, Ct);

        var a = await store.ReadAsync("org-a", Ct);
        var b = await store.ReadAsync("org-b", Ct);

        Assert.Equal(3, a.Count);
        Assert.Null(a[0].PreviousHash);
        Assert.Equal(a[0].Hash, a[1].PreviousHash);
        Assert.Equal(a[1].Hash, a[2].PreviousHash);
        Assert.Null(b[0].PreviousHash);
        Assert.Equal(b[0].Hash, b[1].PreviousHash);
        var verification = await AuditHashChain.VerifyAsync(ToAsync(a.Select(e => e.ToChainEntry())), Ct);
        Assert.True(verification.IsIntact);
        Assert.Equal(3, verification.EntriesChecked);
    }

    [Fact]
    public async Task Store_RefusesUpdateAndDelete()
    {
        var store = new InMemoryAdminAuditStore();
        var log = NewLog(NewKey(), new SettableTime(T0), store);
        var entry = await log.RecordAsync("org-a", AdminAuditAction.Deny, "alice", "request-1", AdminAuditChannel.Web, Ct);

        await Assert.ThrowsAsync<AdminAuditAppendOnlyException>(async () => await store.UpdateAsync(entry.Id, Ct));
        await Assert.ThrowsAsync<AdminAuditAppendOnlyException>(async () => await store.DeleteAsync(entry.Id, Ct));

        var after = await store.ReadAsync("org-a", Ct);
        Assert.Equal(entry, Assert.Single(after));
    }

    [Theory]
    [InlineData("line one\nline two")]
    [InlineData("tok\u0000en")]
    public async Task Entry_RefusesContentInPlaceOfAnIdentifier(string target)
    {
        var log = NewLog(NewKey(), new SettableTime(T0));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await log.RecordAsync("org-a", AdminAuditAction.Publish, "alice", target, AdminAuditChannel.Git, Ct));
    }

    [Fact]
    public async Task Entry_RefusesFileContentsAsTarget()
    {
        var log = NewLog(NewKey(), new SettableTime(T0));
        var contents = new string('x', AdminAuditEntry.MaxFieldLength + 1);
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await log.RecordAsync("org-a", AdminAuditAction.Publish, "alice", contents, AdminAuditChannel.Git, Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await log.RecordAsync("org-a", AdminAuditAction.Publish, contents, "config-1", AdminAuditChannel.Git, Ct));
    }

    [Fact]
    public async Task Export_EndsWithHeadSignedByTheDeploymentKey()
    {
        var key = NewKey();
        var time = new SettableTime(T0);
        var store = new InMemoryAdminAuditStore();
        var log = NewLog(key, time, store);
        await SeedAsync(log, "org-a", 3, Ct);
        time.Now = T0.AddHours(1);

        var bytes = await log.ExportAsync("org-a", Ct);

        using var doc = JsonDocument.Parse(bytes);
        var props = doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.Equal("head", props[^1]);
        var head = doc.RootElement.GetProperty("head");
        Assert.Equal(3, head.GetProperty("count").GetInt64());
        Assert.Equal("org-a", head.GetProperty("organisation").GetString());
        Assert.Equal((await store.ReadAsync("org-a", Ct))[^1].Hash, head.GetProperty("last_hash").GetString());
        Assert.Equal(key.KeyId, head.GetProperty("key_id").GetString());
        var result = await AdminAuditExportVerifier.VerifyAsync(bytes, Pin(key), "org-a", null, Ct);
        Assert.True(result.IsValid);
        Assert.Equal(T0.AddHours(1), result.ExportedAt);
    }

    [Fact]
    public async Task Endpoint_ExportsForACallerAllowedOnTheOrganisation()
    {
        var seed = Ed25519Crypto.NewSeed();
        var key = new ProfileSigningKey(seed);
        using var host = await StartAsync(seed);
        var log = host.Services.GetRequiredService<AdminAuditLog>();
        await SeedAsync(log, "org-a", 2, Ct);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Org", "org-a");

        var response = await client.GetAsync("/ai-sentinel/admin-audit/org-a/export", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var bytes = await response.Content.ReadAsByteArrayAsync(Ct);
        Assert.True((await AdminAuditExportVerifier.VerifyAsync(bytes, Pin(key), "org-a", null, Ct)).IsValid);
    }

    [Fact]
    public async Task Endpoint_RefusesACallerNotAllowedOnTheOrganisation()
    {
        using var host = await StartAsync(Ed25519Crypto.NewSeed());
        var log = host.Services.GetRequiredService<AdminAuditLog>();
        await SeedAsync(log, "org-b", 2, Ct);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Org", "org-a");

        var response = await client.GetAsync("/ai-sentinel/admin-audit/org-b/export", Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain("request-", await response.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Endpoint_RefusesAnAnonymousCaller()
    {
        using var host = await StartAsync(Ed25519Crypto.NewSeed());
        var response = await host.GetTestClient().GetAsync("/ai-sentinel/admin-audit/org-a/export", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Endpoint_UsesTheConfiguredPolicyName()
    {
        using var host = await StartAsync(Ed25519Crypto.NewSeed(), policy: "my-audit-policy");
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Org", "org-a");
        var response = await client.GetAsync("/ai-sentinel/admin-audit/org-a/export", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Endpoint_IsNotMappedUnlessTheHostAsks()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s => s.AddRouting());
                web.Configure(app => app.UseRouting().UseEndpoints(_ => { }));
            })
            .StartAsync(Ct);
        var response = await host.GetTestClient().GetAsync("/ai-sentinel/admin-audit/org-a/export", Ct);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static async Task<IHost> StartAsync(byte[] seed, string policy = "AISentinelAdminAudit")
    {
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthorization(o => o.AddPolicy(policy, p => p.AddRequirements(new OrgRequirement())));
                    s.AddSingleton<IAuthorizationHandler, OrgHandler>();
                    s.AddAISentinelAdminAudit(o =>
                    {
                        o.PolicyName = policy;
                        o.SigningKey = Convert.ToBase64String(seed);
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
                    app.UseEndpoints(e => e.MapAISentinelAdminAudit());
                });
            })
            .StartAsync(Ct);
    }

    private static async IAsyncEnumerable<AuditEntry> ToAsync(IEnumerable<AuditEntry> entries)
    {
        foreach (var e in entries)
        {
            yield return e;
        }
        await Task.CompletedTask;
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
