using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

public sealed class ProfileRefreshTests : IAsyncDisposable
{
    private static readonly Uri Server = new("http://localhost");

    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly FakePolicyServer _server = new();
    private readonly ResidentState _state;
    private readonly ResidentService _service;
    private readonly CancellationTokenSource _stop = new();
    private readonly HttpClient _http;
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _log = new();
    private Task? _run;

    public ProfileRefreshTests()
    {
        _state = new ResidentState(ResidentPaths.Prepare(new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));
        _state.WritePinnedKeys(FakePolicyServer.Organisation, _server.Pinned);
        _service = new ResidentService([new ChildProcessCompiler()], null, new PauseBoard(_state));
        _http = new HttpClient(_server);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ServerLinkTiming Timing(TimeSpan? minGap = null) => new(
        TimeSpan.FromMilliseconds(30), TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(10),
        TimeSpan.FromMilliseconds(30), TimeSpan.FromMilliseconds(100), minGap ?? TimeSpan.FromMilliseconds(200), TimeSpan.FromDays(1));

    private ProfileRefresher StartLink(ServerLinkTiming timing)
    {
        var refresher = new ProfileRefresher(_state, _http, Server, _service, timing, TimeProvider.System, _log.Enqueue);
        var link = new ServerLink(_http, Server, new PauseBoard(_state), refresher, timing, TimeProvider.System, _log.Enqueue);
        _run = Task.Run(() => link.RunAsync(_stop.Token), Ct);
        return refresher;
    }

    private string Decide(string tool, string input)
    {
        var json = PolicyInputSerializer.Serialize(PolicyInputBuilder.Build(PolicyClis.ClaudeCode, tool, JsonDocument.Parse(input).RootElement, "s-1", [], "/work/repo"));
        var answer = _service.Answer(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = "*", Input = json });
        return answer.Ok ? answer.Outcome! : "error:" + answer.Error;
    }

    private string Shell() => Decide("Bash", """{"command":"ls"}""");

    private string Fetch() => Decide("WebFetch", """{"url":"https://example.com"}""");

    private static async Task WaitForAsync(Func<bool> condition, string what, int seconds = 60)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("timed out waiting for " + what);
            }

            await Task.Delay(20, Ct);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        if (_run is not null)
        {
            await _run.WaitAsync(TimeSpan.FromSeconds(30));
        }

        _http.Dispose();
        _service.Dispose();
        _stop.Dispose();
        ResidentTestSupport.Delete(_dir);
    }

    [Fact]
    public async Task The_profile_is_fetched_at_start_verified_cached_and_made_the_warm_module()
    {
        _ = StartLink(Timing());

        await WaitForAsync(() => Shell() is "deny", "the first profile");

        Assert.Equal("defer", Fetch());
        var cached = _state.ReadProfile(_server.Pinned, "acme", "*", DateTimeOffset.UtcNow, CachedNodePolicies.SlotOf("*"));
        Assert.True(cached!.IsAccepted);
        Assert.Equal(1, cached.Profile!.ConfigurationVersion);
    }

    [Fact]
    public async Task A_configuration_published_during_a_disconnect_is_used_by_the_next_resident_decision_after_the_reconnect()
    {
        _ = StartLink(Timing());
        await WaitForAsync(() => Shell() is "deny", "the first profile");

        _server.RefuseConnections(3);
        _server.Drop();
        _server.Version = 2;
        _server.Module = _ => FakePolicyServer.Rule("deny contains \"v2\" if input.kind == \"fetch\"");
        await WaitForAsync(() => Fetch() is "deny", "the second configuration");

        Assert.Equal("defer", Shell());
        Assert.Equal(2, _server.Connections);
        Assert.Equal(2, _state.ReadProfile(_server.Pinned, "acme", "*", DateTimeOffset.UtcNow, CachedNodePolicies.SlotOf("*"))!.Profile!.ConfigurationVersion);
    }

    [Fact]
    public async Task A_configuration_the_server_announces_is_fetched_and_replaces_the_warm_module()
    {
        _ = StartLink(Timing());
        await WaitForAsync(() => Shell() is "deny", "the first profile");

        _server.Version = 2;
        _server.Module = _ => FakePolicyServer.Rule("deny contains \"v2\" if input.kind == \"fetch\"");
        _server.Push("configuration", """{"version":2}""");
        await WaitForAsync(() => Fetch() is "deny", "the announced configuration");

        Assert.Equal("defer", Shell());
        Assert.Equal(1, _server.Connections);
    }

    [Fact]
    public async Task A_fetch_that_fails_once_after_a_reconnect_succeeds_on_retry_without_another_trigger()
    {
        _server.FailProfiles(1);
        _ = StartLink(Timing());

        await WaitForAsync(() => Shell() is "deny", "the retried fetch");

        Assert.Equal(2, _server.ProfileRequests);
        Assert.Equal(1, _server.Connections);
    }

    [Fact]
    public async Task While_a_fetch_keeps_failing_the_last_valid_profile_stays_in_force_and_the_retries_are_bounded()
    {
        var refresher = StartLink(Timing());
        await WaitForAsync(() => Shell() is "deny", "the first profile");
        var before = _server.ProfileRequests;

        _server.Version = 2;
        _server.Module = _ => FakePolicyServer.Rule("deny contains \"v2\" if input.kind == \"fetch\"");
        _server.FailProfiles(1000);
        _server.Push("configuration", """{"version":2}""");
        await Task.Delay(1200, Ct);

        Assert.Equal("deny", Shell());
        Assert.Equal("defer", Fetch());
        Assert.Equal(1, refresher.HeldVersionOf("*"));
        // Backoff doubles from 30 ms up to a 100 ms ceiling, so a second is a handful of attempts and not a loop.
        Assert.InRange(_server.ProfileRequests - before, 3, 25);
    }

    [Fact]
    public async Task A_profile_that_has_expired_is_not_used_by_the_resident_when_the_refetches_fail()
    {
        _server.Lifetime = TimeSpan.FromSeconds(2);
        _ = StartLink(Timing());
        await WaitForAsync(() => Shell() is "deny", "the first profile");

        _server.FailProfiles(1000);
        await WaitForAsync(() => Shell().StartsWith("error:", StringComparison.Ordinal), "the profile to expire", seconds: 20);

        Assert.Contains("expired", Shell(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_profile_with_a_lifetime_under_a_day_is_refreshed_before_it_expires_from_the_expiry_of_the_one_before()
    {
        _server.Lifetime = TimeSpan.FromSeconds(4);
        _ = StartLink(Timing());
        await WaitForAsync(() => _server.ProfileRequests >= 1 && Shell() is "deny", "the first profile");
        var first = _state.ReadProfile(_server.Pinned, "acme", "*", DateTimeOffset.UtcNow, CachedNodePolicies.SlotOf("*"))!.Profile!;

        await WaitForAsync(() => _server.ProfileRequests >= 2, "the refresh", seconds: 5);

        var second = _server.ProfileTimes[1];
        Assert.True(second < first.ExpiresAt, $"fetched at {second:O}, the profile expired at {first.ExpiresAt:O}");
        await WaitForAsync(
            () => _state.ReadProfile(_server.Pinned, "acme", "*", DateTimeOffset.UtcNow, CachedNodePolicies.SlotOf("*"))?.Profile?.IssuedAt > first.IssuedAt,
            "the fresh profile in the cache", seconds: 5);
        // The next refresh is planned from the fresh expiry, and fetches are held apart: no loop.
        Assert.True(_server.ProfileRequests <= 4, $"{_server.ProfileRequests} fetches");
    }

    [Fact]
    public void A_profile_is_refreshed_a_day_before_it_expires_or_halfway_through_a_shorter_lifetime_and_at_once_when_that_has_passed()
    {
        var timing = ServerLinkTiming.Default;
        var issued = DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

        Assert.Equal(issued.AddDays(6), timing.RefreshAt(issued, issued.AddDays(7)));
        Assert.Equal(issued.AddDays(1), timing.RefreshAt(issued, issued.AddDays(2)));
        Assert.Equal(issued.AddHours(12), timing.RefreshAt(issued, issued.AddHours(24)));
        Assert.Equal(issued.AddMinutes(30), timing.RefreshAt(issued, issued.AddHours(1)));
        Assert.True(timing.RefreshAt(issued, issued.AddHours(24)) < issued.AddHours(24).AddHours(1));
    }

    [Fact]
    public async Task An_older_profile_from_an_overlapping_fetch_does_not_replace_a_newer_one_in_the_cache_or_in_the_warm_module()
    {
        var refresher = new ProfileRefresher(_state, _http, Server, _service, Timing(), TimeProvider.System);
        _server.Version = 2;
        _server.Module = _ => FakePolicyServer.Rule("deny contains \"v2\" if input.kind == \"fetch\"");
        var newer = _server.Issue("*");
        _server.Version = 1;
        _server.Module = _ => FakePolicyServer.Rule("deny contains \"v1\" if input.kind == \"shell\"");
        var older = _server.Issue("*");

        var first = await refresher.OfferAsync("*", newer, Ct);
        var second = await refresher.OfferAsync("*", older, Ct);

        Assert.Equal((ProfileOffer.Installed, ProfileOffer.Stale), (first, second));
        Assert.Equal("deny", Fetch());
        Assert.Equal("defer", Shell());
        Assert.Equal(2, _state.ReadProfile(_server.Pinned, "acme", "*", DateTimeOffset.UtcNow, CachedNodePolicies.SlotOf("*"))!.Profile!.ConfigurationVersion);
    }

    [Fact]
    public async Task A_profile_that_fails_the_check_is_refused_and_leaves_the_one_in_force()
    {
        var refresher = new ProfileRefresher(_state, _http, Server, _service, Timing(), TimeProvider.System);
        var good = _server.Issue("*");
        _ = await refresher.OfferAsync("*", good, Ct);
        _server.Version = 5;
        var forged = _server.Issue("*") with { Signature = Convert.ToBase64String(new byte[64]) };

        var offer = await refresher.OfferAsync("*", forged, Ct);

        Assert.Equal(ProfileOffer.Refused, offer);
        Assert.Equal(1, refresher.HeldVersionOf("*"));
        Assert.Equal("deny", Shell());
    }

    [Fact]
    public async Task An_unchanged_profile_does_not_cause_repeated_fetches()
    {
        var refresher = StartLink(Timing());
        await WaitForAsync(() => Shell() is "deny", "the first profile");
        var after = _server.ProfileRequests;

        _server.Push("configuration", """{"version":1}""");
        _server.Push("configuration", """{"version":1}""");
        await Task.Delay(1000, Ct);

        Assert.Equal(after, _server.ProfileRequests);
        Assert.True(_server.Connections == 1, string.Join(" | ", _log));
        Assert.Equal(1, refresher.HeldVersion);
    }

    [Fact]
    public async Task The_snapshot_of_the_first_connection_does_not_fetch_again_while_the_fetch_at_start_is_still_running()
    {
        _server.ProfileDelay = TimeSpan.FromMilliseconds(400);
        _ = StartLink(Timing());

        await WaitForAsync(() => Shell() is "deny", "the first profile");
        await Task.Delay(800, Ct);

        Assert.Equal(1, _server.ProfileRequests);
    }

    [Fact]
    public async Task The_profile_of_a_repository_the_node_map_names_is_fetched_with_the_organisation_profile_and_the_map_is_cached_for_the_hooks()
    {
        _server.Repositories.Add(FakePolicyServer.Widgets);
        _server.Module = r => r is "*" ? FakePolicyServer.Rule("deny contains \"org\" if input.kind == \"shell\"") : FakePolicyServer.Rule("ask contains \"team\" if input.kind == \"fetch\"");
        var refresher = StartLink(Timing());

        await WaitForAsync(() => refresher.HeldVersionOf(FakePolicyServer.Widgets) is not null && Shell() is "deny", "both profiles");

        Assert.Equal("team-a", _state.ReadNodeMap()!.NodeFor(FakePolicyServer.Widgets));
        var policies = new CachedNodePolicies(_state, _server.Pinned, "acme", () => DateTimeOffset.UtcNow, Path.Combine(_dir, "c2"), [new ChildProcessCompiler()]);
        var fetch = PolicyInputSerializer.Serialize(PolicyInputBuilder.Build(PolicyClis.ClaudeCode, "WebFetch", JsonDocument.Parse("""{"url":"https://example.com"}""").RootElement, "s-1", [], "/work/repo"));
        Assert.Equal(AI.Sentinel.ClaudeCode.DecisionOutcome.Ask, policies.ForRepository(FakePolicyServer.Widgets, fetch)!.Outcome);
    }
}
