using System.Net;
using System.Text.Json;
using AI.Sentinel.AspNetCore.PolicyFolder;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.Events.ServerEventTestHost;

namespace AI.Sentinel.Tests.AspNetCore.Events;

public sealed class TeamVisibilityTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    internal static string Nodes(string namesOnTeamA) => """
        {
          "organisation": "acme",
          "nodes": [
            {"id": "acme", "kind": "organisation"},
            {"id": "team-a", "kind": "team", "settings": @SETTINGS@},
            {"id": "team-b", "kind": "team"}
          ],
          "repositories": {"github.com/acme/widgets": "team-a", "github.com/acme/gadgets": "team-b"},
          "roles": [
            {"group": "sec", "role": "administrator", "node": "acme"},
            {"group": "leads-a", "role": "team_lead", "node": "team-a"},
            {"group": "leads-b", "role": "team_lead", "node": "team-b"}
          ]
        }
        """.Replace("@SETTINGS@", namesOnTeamA, StringComparison.Ordinal);

    internal static readonly string NamesOn = Nodes("""{"names": {"show": true, "approval_reference": "DPIA-7"}}""");

    private static readonly string NamesOff = Nodes("{}");

    private static async Task SendAsync(ServerEventTestHost host, string developer, string id, string node = "team-a") =>
        await host.SendAsync(Post(Batch("acme", Event(id, node: node)), "acme", developer));

    private static async Task FillAsync(ServerEventTestHost host)
    {
        foreach (var d in new[] { "a1", "a2", "a3" })
        {
            await SendAsync(host, d, "ev-" + d);
        }

        foreach (var d in new[] { "b1", "b2" })
        {
            await SendAsync(host, d, "ev-" + d, "team-b");
        }
    }

    private static bool Is(string? actual, string expected) => string.Equals(actual, expected, StringComparison.Ordinal);

    private static string? NodeOf(JsonElement e) => e.GetProperty("node").GetString();

    private static string? IdOf(JsonElement e) => e.GetProperty("event_id").GetString();

    private static async Task<JsonElement[]> ReadAsync(ServerEventTestHost host, string path, string sub, string groups)
    {
        var response = await host.SendAsync(Get(path, "acme", sub, groups));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        return [.. document.RootElement.GetProperty("events").EnumerateArray().Select(e => e.Clone())];
    }

    [Fact]
    public async Task Without_the_names_setting_the_answers_hold_no_developer_or_code()
    {
        using var host = await StartAsync(nodes: NamesOff);
        await FillAsync(host);

        var text = await (await host.SendAsync(Get("acme/audit", "acme", "root", "sec"))).Content.ReadAsStringAsync(Ct);

        Assert.DoesNotContain("dev-", text, StringComparison.Ordinal);
        Assert.DoesNotContain("\"developer\"", text, StringComparison.Ordinal);
        Assert.Contains("\"ev-a1\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_names_setting_shows_codes_for_the_node_that_has_it_with_a_reference()
    {
        using var host = await StartAsync(nodes: NamesOn);
        await FillAsync(host);

        var events = await ReadAsync(host, "acme/audit", "root", "sec");

        Assert.Equal(["ev-a1", "ev-a2", "ev-a3"], events.Where(e => Is(NodeOf(e), "team-a")).Select(IdOf).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.Equal(["ev-b1", "ev-b2"], events.Where(e => !Is(NodeOf(e), "team-a")).Select(IdOf).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.All(events.Where(e => Is(NodeOf(e), "team-a")), e => Assert.StartsWith("dev-", e.GetProperty("developer").GetString(), StringComparison.Ordinal));
        Assert.All(events.Where(e => !Is(NodeOf(e), "team-a")), e => Assert.False(e.TryGetProperty("developer", out _)));
    }

    [Fact]
    public async Task A_small_team_shown_under_the_organisation_follows_the_names_setting_of_the_organisation()
    {
        using var host = await StartAsync(nodes: NamesOn);
        await SendAsync(host, "a1", "ev-a1");
        await SendAsync(host, "a2", "ev-a2");

        var events = await ReadAsync(host, "acme/audit", "root", "sec");

        Assert.Equal(["ev-a1", "ev-a2"], events.Select(IdOf).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.All(events, e => Assert.Equal("acme", NodeOf(e)));
        Assert.All(events, e => Assert.False(e.TryGetProperty("developer", out _)));
    }

    [Theory]
    [InlineData("""{"names": {"show": true}}""")]
    [InlineData("""{"names": {"show": true, "approval_reference": "  "}}""")]
    public void The_names_setting_is_refused_without_an_approval_reference(string settings)
    {
        var json = System.Text.Encoding.UTF8.GetBytes(Nodes(settings));

        Assert.Throws<InvalidDataException>(() => NodeConfiguration.Parse(json));
    }

    [Fact]
    public async Task A_team_under_three_people_shows_only_as_part_of_the_organisation()
    {
        using var host = await StartAsync(nodes: NamesOff);
        await FillAsync(host);

        var all = await ReadAsync(host, "acme/audit", "root", "sec");

        Assert.Equal(3, all.Count(e => Is(NodeOf(e), "team-a")));
        Assert.Equal(2, all.Count(e => Is(NodeOf(e), "acme")));
        Assert.Empty(await ReadAsync(host, "acme/audit?node=team-b", "root", "sec"));
        Assert.Equal(2, (await ReadAsync(host, "acme/audit?node=acme", "root", "sec")).Length);
        Assert.Empty(await ReadAsync(host, "acme/audit", "lena-b", "leads-b"));
        Assert.Equal(3, (await ReadAsync(host, "acme/audit", "lena", "leads-a")).Length);
    }

    [Fact]
    public async Task A_team_that_sent_only_a_gap_shows_its_gap_under_the_organisation()
    {
        using var host = await StartAsync(nodes: NamesOff);
        await host.SendAsync(Post("""{"organisation":"acme","events":[],"gap":{"pruned":4,"node":"team-b"}}""", "acme", "b1"));

        async Task<JsonElement[]> GapsAsync(string sub, string groups)
        {
            var response = await host.SendAsync(Get("acme/audit", "acme", sub, groups));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
            return [.. document.RootElement.GetProperty("gaps").EnumerateArray().Select(g => g.Clone())];
        }

        Assert.Empty(await GapsAsync("lena-b", "leads-b"));
        var seen = Assert.Single(await GapsAsync("root", "sec"));
        Assert.Equal("acme", NodeOf(seen));
    }

    [Fact]
    public async Task Each_record_is_stamped_with_the_visibility_in_force_when_it_was_stored()
    {
        using var host = await StartAsync(nodes: NamesOn);
        await SendAsync(host, "a1", "while-on");
        await host.RepublishAsync(NamesOff, "v2");
        await SendAsync(host, "a1", "while-off");

        var stored = (await host.Store.ReadEventsAsync("acme", Ct)).ToDictionary(e => e.Id, e => e.Visibility, StringComparer.Ordinal);

        Assert.Equal("names", stored["while-on"]);
        Assert.Equal("teams", stored["while-off"]);
    }

    [Fact]
    public async Task Turning_names_off_hides_them_at_once_also_in_records_stored_while_it_was_on()
    {
        using var host = await StartAsync(o => o.MinimumTeamPeople = 1, NamesOn);
        await SendAsync(host, "a1", "while-on");
        Assert.True((await ReadAsync(host, "acme/audit", "root", "sec"))[0].TryGetProperty("developer", out _));

        await host.RepublishAsync(NamesOff, "v2");

        var after = await ReadAsync(host, "acme/audit", "root", "sec");
        Assert.False(after[0].TryGetProperty("developer", out _));
        Assert.Equal("names", after[0].GetProperty("visibility").GetString());

        // Turned on again, a record stored while it was off stays without a name.
        await SendAsync(host, "a1", "while-off");
        await host.RepublishAsync(NamesOn, "v3");
        var again = await ReadAsync(host, "acme/audit", "root", "sec");
        Assert.True(again.Single(e => Is(IdOf(e), "while-on")).TryGetProperty("developer", out _));
        Assert.False(again.Single(e => Is(IdOf(e), "while-off")).TryGetProperty("developer", out _));
    }

    [Fact]
    public async Task A_developer_still_sees_their_own_decisions_with_their_code()
    {
        using var host = await StartAsync(nodes: NamesOff);
        await FillAsync(host);

        var own = await ReadAsync(host, "acme/audit", "b1", "");

        var one = Assert.Single(own);
        Assert.Equal("ev-b1", one.GetProperty("event_id").GetString());
        Assert.StartsWith("dev-", one.GetProperty("developer").GetString(), StringComparison.Ordinal);
    }
}
