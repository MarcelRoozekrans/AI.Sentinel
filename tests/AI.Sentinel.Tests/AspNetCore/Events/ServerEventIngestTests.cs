using System.Net;
using System.Text.Json;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.Events;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.Events.ServerEventTestHost;

namespace AI.Sentinel.Tests.AspNetCore.Events;

public sealed class ServerEventIngestTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<IReadOnlyList<ServerEvent>> StoredAsync(ServerEventTestHost host) =>
        await host.Store.ReadEventsAsync("acme", Ct);

    [Fact]
    public async Task Only_the_allowlisted_fields_are_kept_and_the_names_of_the_others_are_counted()
    {
        using var host = await StartAsync();
        var json = Batch("acme", Event("e-1", extra: ",\"command\":\"rm -rf /secret\",\"path\":\"/home/x\",\"tool_input\":{\"a\":1},\"command2\":\"x\""));

        var response = await host.SendAsync(Post(json, "acme"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var stored = Assert.Single(await StoredAsync(host));
        Assert.Equal(("shell", "deny", "team-a", "s-1"), (stored.ToolKind, stored.Outcome, stored.Node, stored.Session));
        Assert.Equal(["p1"], stored.Policies);
        Assert.DoesNotContain("rm -rf", stored.ToString(), StringComparison.Ordinal);
        var dropped = await host.Store.ReadDroppedAsync("acme", Ct);
        Assert.Equal(1, dropped["command"]);
        Assert.Equal(1, dropped["path"]);
        Assert.Equal(1, dropped["tool_input"]);
        Assert.False(dropped.ContainsKey("rm -rf /secret"));
    }

    [Fact]
    public async Task Every_allowlisted_field_is_kept()
    {
        using var host = await StartAsync();
        var full = """{"event_id":"e-9","at":"2026-11-23T09:00:00Z","tool_kind":"shell","outcome":"deny","policies":["p1","p2"],"policy_version":"v7","decided":"local","node":"team-a","cli":"claude-code","session":"s-9","detector":"SEC-01","severity":"high","redactions":{"secret":2},"reason":"matched"}""";

        await host.SendAsync(Post(Batch("acme", full), "acme"));

        var e = Assert.Single(await StoredAsync(host));
        Assert.Equal(("v7", "local", "claude-code", "SEC-01", "high", "matched"), (e.PolicyVersion, e.DecidedAt, e.Cli, e.Detector, e.Severity, e.Reason));
        Assert.Equal(["p1", "p2"], e.Policies);
        Assert.Equal(2, e.Redactions["secret"]);
        Assert.Equal(new DateTimeOffset(2026, 11, 23, 9, 0, 0, TimeSpan.Zero), e.At);
    }

    [Fact]
    public async Task Reason_text_is_kept_only_for_a_node_with_detailed_logging()
    {
        using var host = await StartAsync();

        await host.SendAsync(Post(Batch("acme",
            Event("e-1", node: "team-a", extra: ",\"reason\":\"why a\""),
            Event("e-2", node: "team-b", extra: ",\"reason\":\"why b\"")), "acme"));

        var stored = (await StoredAsync(host)).ToDictionary(e => e.Id, StringComparer.Ordinal);
        Assert.Equal("why a", stored["e-1"].Reason);
        Assert.Null(stored["e-2"].Reason);
        Assert.Equal(1, (await host.Store.ReadDroppedAsync("acme", Ct))["reason"]);
    }

    [Fact]
    public async Task The_developer_is_replaced_by_a_per_organisation_code_and_the_key_is_not_in_the_store()
    {
        using var host = await StartAsync();

        await host.SendAsync(Post(Batch("acme", Event("e-1")), "acme", "alice"));
        await host.SendAsync(Post(Batch("acme", Event("e-2")), "acme", "alice"));
        await host.SendAsync(Post(Batch("acme", Event("e-3")), "acme", "bob"));

        var stored = await StoredAsync(host);
        Assert.DoesNotContain(stored, e => e.ToString()!.Contains("alice", StringComparison.Ordinal) || e.ToString()!.Contains("bob", StringComparison.Ordinal));
        Assert.Equal(stored[0].Developer, stored[1].Developer);
        Assert.NotEqual(stored[0].Developer, stored[2].Developer, StringComparer.Ordinal);
        var keys = new PseudonymKeys(Key);
        Assert.Equal(keys.CodeFor("acme", "alice"), stored[0].Developer);
        Assert.NotEqual(keys.CodeFor("acme", "alice"), keys.CodeFor("other", "alice"), StringComparer.Ordinal);
        Assert.NotEqual(keys.CodeFor("acme", "alice"), new PseudonymKeys(Convert.ToBase64String(new byte[32].Select(_ => (byte)9).ToArray())).CodeFor("acme", "alice"), StringComparer.Ordinal);
        // The store is an interface that has no way to reach the key or an identity.
        Assert.DoesNotContain(typeof(IServerEventStore).GetMethods().SelectMany(m => m.GetParameters()), p => p.ParameterType == typeof(PseudonymKeys));
    }

    [Fact]
    public async Task Events_are_deleted_after_90_days_and_daily_counts_after_13_months_by_default()
    {
        using var host = await StartAsync();
        await host.SendAsync(Post(Batch("acme", Event("e-1")), "acme"));

        host.Time.Advance(TimeSpan.FromDays(89));
        await host.SendAsync(Post(Batch("acme", Event("e-2")), "acme"));
        Assert.Equal(2, (await StoredAsync(host)).Count);

        host.Time.Advance(TimeSpan.FromDays(2));
        await host.SendAsync(Post(Batch("acme", Event("e-3")), "acme"));
        Assert.Equal(["e-2", "e-3"], (await StoredAsync(host)).Select(e => e.Id).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.Equal(3, (await host.Store.ReadDailyCountsAsync("acme", Ct)).Sum(c => c.Count));

        host.Time.Advance(TimeSpan.FromDays(31 * 13));
        await host.SendAsync(Post(Batch("acme", Event("e-4")), "acme"));
        var counts = await host.Store.ReadDailyCountsAsync("acme", Ct);
        Assert.Equal(1, counts.Sum(c => c.Count));
        Assert.Equal(DateOnly.FromDateTime(host.Time.GetUtcNow().UtcDateTime), Assert.Single(counts).Day);
    }

    [Fact]
    public async Task Retention_can_be_set_for_one_organisation()
    {
        using var host = await StartAsync(o => o.Retention["acme"] = new ServerEventRetention { EventDays = 10, DailyCountMonths = 2 });
        await host.SendAsync(Post(Batch("acme", Event("e-1")), "acme"));

        host.Time.Advance(TimeSpan.FromDays(11));
        await host.SendAsync(Post(Batch("acme", Event("e-2")), "acme"));
        Assert.Equal("e-2", Assert.Single(await StoredAsync(host)).Id);
        Assert.Equal(2, (await host.Store.ReadDailyCountsAsync("acme", Ct)).Sum(c => c.Count));

        host.Time.Advance(TimeSpan.FromDays(70));
        await host.SendAsync(Post(Batch("acme", Event("e-3")), "acme"));
        Assert.Equal(1, (await host.Store.ReadDailyCountsAsync("acme", Ct)).Sum(c => c.Count));
    }

    [Fact]
    public async Task The_same_event_id_is_stored_once_and_distinct_events_with_equal_fields_are_both_stored()
    {
        using var host = await StartAsync();

        await host.SendAsync(Post(Batch("acme", Event("e-1")), "acme"));
        var again = await host.SendAsync(Post(Batch("acme", Event("e-1"), Event("e-2"), Event("e-3")), "acme"));

        Assert.Equal(["e-1", "e-2", "e-3"], (await StoredAsync(host)).Select(e => e.Id).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.Contains("\"accepted\":2,\"duplicates\":1", await again.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        Assert.Equal(3, (await host.Store.ReadDailyCountsAsync("acme", Ct)).Sum(c => c.Count));
    }

    [Fact]
    public async Task An_unauthenticated_batch_is_refused_and_nothing_is_stored()
    {
        using var host = await StartAsync();

        var response = await host.SendAsync(Post(Batch("acme", Event("e-1")), org: null, sub: null));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(await StoredAsync(host));
    }

    [Fact]
    public async Task A_sender_the_host_policy_refuses_stores_nothing()
    {
        using var host = await StartAsync();

        var response = await host.SendAsync(Post(Batch("acme", Event("e-1")), "elsewhere"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await StoredAsync(host));
    }

    [Fact]
    public async Task The_organisation_comes_from_the_sender_so_a_batch_for_another_one_is_refused_and_nothing_is_stored()
    {
        using var host = await StartAsync();

        var response = await host.SendAsync(Post(Batch("rival", Event("e-1")), "acme"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await StoredAsync(host));
        Assert.Empty(await host.Store.ReadEventsAsync("rival", Ct));
        Assert.Empty(await host.Store.ReadDroppedAsync("acme", Ct));
    }

    [Fact]
    public async Task The_sender_organisation_can_come_from_a_claim_of_the_token()
    {
        using var host = await StartAsync(o => o.OrganisationClaim = "org");

        var accepted = await host.SendAsync(Post(Batch("acme", Event("e-1")), "acme"));
        var refused = await host.SendAsync(Post(Batch("acme", Event("e-2")), "rival"));

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Single(await StoredAsync(host));
    }

    [Fact]
    public async Task A_gap_report_with_a_count_of_pruned_events_is_stored_and_readable()
    {
        using var host = await StartAsync();
        var json = Batch("acme", Event("e-1")).TrimEnd('}') + ",\"gap\":{\"pruned\":7,\"node\":\"team-a\"}}";

        await host.SendAsync(Post(json, "acme"));

        var gap = Assert.Single(await host.Store.ReadGapsAsync("acme", Ct));
        Assert.Equal((7, "team-a"), (gap.Pruned, gap.Node));
        var read = await host.SendAsync(Get("acme/audit", "acme", "root", "sec"));
        using var document = JsonDocument.Parse(await read.Content.ReadAsStringAsync(Ct));
        Assert.Equal(7, document.RootElement.GetProperty("gaps")[0].GetProperty("pruned").GetInt32());
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"events\":[]}")]
    public async Task A_body_that_is_not_a_batch_is_a_bad_request(string body)
    {
        using var host = await StartAsync();

        Assert.Equal(HttpStatusCode.BadRequest, (await host.SendAsync(Post(body, "acme"))).StatusCode);
    }

    [Fact]
    public async Task An_event_of_the_wrong_shape_is_rejected_and_the_rest_of_the_batch_is_stored()
    {
        using var host = await StartAsync();
        var bad = """{"event_id":"e-bad","tool_kind":"shell","outcome":"deny","policies":"p1"}""";

        var response = await host.SendAsync(Post(Batch("acme", bad, Event("e-1")), "acme"));

        Assert.Contains("\"rejected\":1", await response.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        Assert.Equal("e-1", Assert.Single(await StoredAsync(host)).Id);
    }

    [Fact]
    public async Task A_batch_over_the_size_limit_is_refused()
    {
        using var host = await StartAsync();
        var big = Batch("acme", Event("e-1", extra: ",\"reason\":\"" + new string('x', 30_000) + "\""));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await host.SendAsync(Post(big, "acme"))).StatusCode);
        Assert.Empty(await StoredAsync(host));
    }
}
