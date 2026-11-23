using System.Net;
using System.Text.Json;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.Events.ServerEventTestHost;

namespace AI.Sentinel.Tests.AspNetCore.Events;

public sealed class ServerEventReadTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<ServerEventTestHost> SeededAsync()
    {
        var host = await StartAsync(o => o.MinimumTeamPeople = 1);
        await host.SendAsync(Post(Batch("acme",
            Event("a-deny", "deny", "team-a", "s-1", ",\"at\":\"2026-11-23T09:00:00Z\""),
            Event("a-allow", "allow", "team-a", "s-2", ",\"at\":\"2026-11-23T11:00:00Z\"")), "acme", "alice"));
        await host.SendAsync(Post(Batch("acme", Event("b-deny", "deny", "team-b", "s-3", ",\"at\":\"2026-11-23T10:00:00Z\"")), "acme", "bob"));
        return host;
    }

    private static async Task<string[]> IdsAsync(ServerEventTestHost host, string path, string sub, string groups, string org = "acme")
    {
        var response = await host.SendAsync(Get(path, org, sub, groups));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        return [.. document.RootElement.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("event_id").GetString()!)];
    }

    [Fact]
    public async Task Blocked_calls_are_the_denied_events_and_the_audit_trail_is_every_event()
    {
        using var host = await SeededAsync();

        Assert.Equal(["a-deny", "b-deny"], await IdsAsync(host, "acme/blocked", "root", "sec"));
        Assert.Equal(["a-deny", "b-deny", "a-allow"], await IdsAsync(host, "acme/audit", "root", "sec"));
    }

    [Fact]
    public async Task The_reads_filter_on_node_session_and_time()
    {
        using var host = await SeededAsync();

        Assert.Equal(["a-deny", "a-allow"], await IdsAsync(host, "acme/audit?node=team-a", "root", "sec"));
        Assert.Equal(["b-deny"], await IdsAsync(host, "acme/audit?session=s-3", "root", "sec"));
        Assert.Equal(["b-deny", "a-allow"], await IdsAsync(host, "acme/audit?from=2026-11-23T09:30:00Z", "root", "sec"));
        Assert.Equal(["a-deny"], await IdsAsync(host, "acme/audit?to=2026-11-23T09:30:00Z", "root", "sec"));
        Assert.Equal(["a-deny"], await IdsAsync(host, "acme/blocked?node=team-a&from=2026-11-23T08:00:00Z&to=2026-11-23T09:30:00Z", "root", "sec"));
        Assert.Equal(HttpStatusCode.BadRequest, (await host.SendAsync(Get("acme/audit?from=yesterday", "acme", "root", "sec"))).StatusCode);
    }

    [Fact]
    public async Task A_team_lead_reads_their_node_and_a_developer_their_own_decisions()
    {
        using var host = await SeededAsync();

        Assert.Equal(["a-deny", "a-allow"], await IdsAsync(host, "acme/audit", "lena", "leads-a"));
        Assert.Equal(["b-deny"], await IdsAsync(host, "acme/audit", "lena-b", "leads-b"));
        Assert.Equal(["a-deny", "a-allow"], await IdsAsync(host, "acme/audit", "alice", ""));
        Assert.Equal(["b-deny"], await IdsAsync(host, "acme/blocked", "bob", ""));
        Assert.Empty(await IdsAsync(host, "acme/audit", "carol", ""));
        Assert.Equal(["b-deny"], await IdsAsync(host, "acme/audit?node=team-b", "lena", "leads-a,leads-b"));
    }

    [Fact]
    public async Task The_answers_show_a_code_for_the_developer_and_never_a_name()
    {
        using var host = await StartAsync(o => o.MinimumTeamPeople = 1, TeamVisibilityTests.NamesOn);
        await host.SendAsync(Post(Batch("acme", Event("a-deny")), "acme", "alice"));
        await host.SendAsync(Post(Batch("acme", Event("b-deny", node: "team-b")), "acme", "bob"));

        var response = await host.SendAsync(Get("acme/audit", "acme", "root", "sec"));

        var text = await response.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("alice", text, StringComparison.Ordinal);
        Assert.DoesNotContain("bob", text, StringComparison.Ordinal);
        Assert.Contains("\"developer\":\"dev-", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unauthenticated_read_is_refused()
    {
        using var host = await SeededAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(Get("acme/audit", org: null, sub: null))).StatusCode);
    }

    [Fact]
    public async Task The_host_policy_decides_first_and_another_organisation_is_not_served()
    {
        using var host = await SeededAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await host.SendAsync(Get("acme/audit", "elsewhere", "root", "sec"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.SendAsync(Get("rival/audit", "rival", "root", "sec"))).StatusCode);
    }
}
