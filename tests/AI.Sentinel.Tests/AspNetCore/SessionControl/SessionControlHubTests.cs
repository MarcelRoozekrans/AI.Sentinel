using AI.Sentinel.AspNetCore.SessionControl;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Tests.AspNetCore.PolicyFolder;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore.SessionControl;

public sealed class SessionControlHubTests : IDisposable
{
    private const string Widgets = "github.com/acme/widgets";
    private const string Gadgets = "github.com/acme/gadgets";

    private readonly PolicyFolderFixture _folder = new();
    private readonly SettableTime _time = new(DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
    private readonly SessionControlHub _hub;

    public SessionControlHubTests() => _hub = new SessionControlHub(_folder.Loader, _time);

    public void Dispose()
    {
        _hub.Dispose();
        _folder.Dispose();
    }

    [Fact]
    public void A_pause_in_force_is_kept_when_the_caller_may_not_replace_it_and_nothing_is_announced()
    {
        _ = _hub.Pause("s-1", Widgets, "first", null, _ => true);
        using var stream = _hub.Subscribe();

        var refused = _hub.Pause("s-1", Gadgets, "second", null, repository => string.Equals(repository, Gadgets, StringComparison.Ordinal));

        Assert.Null(refused);
        Assert.Equal(Widgets, _hub.Find("s-1")!.Repository);
        Assert.Equal("first", _hub.Find("s-1")!.Pause.Reason);
        Assert.False(stream.Events.TryRead(out _));
    }

    [Fact]
    public void A_timed_pause_that_has_lapsed_is_dropped_from_the_find_the_list_and_the_snapshot_and_a_pause_without_an_end_stays()
    {
        _ = _hub.Pause("timed", Widgets, null, _time.Now.AddMinutes(5), _ => true);
        _ = _hub.Pause("open", Widgets, null, null, _ => true);
        Assert.Equal(2, _hub.List().Count);

        _time.Now = _time.Now.AddMinutes(5);

        Assert.Null(_hub.Find("timed"));
        Assert.Equal<string>(["open"], _hub.List().Select(h => h.Pause.Session).ToArray());
        using var stream = _hub.Subscribe();
        Assert.Equal<string>(["open"], stream.Snapshot.Pauses.Select(p => p.Session).ToArray());
    }

    [Fact]
    public async Task A_stream_that_falls_behind_is_closed_with_an_error_so_its_client_reconnects_and_the_other_streams_keep_their_events()
    {
        using var slow = _hub.Subscribe();
        for (var i = 0; i < 256; i++)
        {
            _ = _hub.Pause($"s-{i}", Widgets, null, null, _ => true);
        }

        using var healthy = _hub.Subscribe();
        _ = _hub.Pause("overflow", Widgets, null, null, _ => true);

        // The reader sees every event that was queued, and then the failure.
        var queued = 0;
        while (slow.Events.TryRead(out _))
        {
            queued++;
        }

        Assert.Equal(256, queued);
        _ = await Assert.ThrowsAsync<IOException>(() => slow.Events.Completion);
        Assert.True(healthy.Events.TryRead(out var frame));
        Assert.Equal(SessionEventNames.Pause, frame!.Event);
        Assert.Contains("overflow", frame.Data, StringComparison.Ordinal);
    }

    [Fact]
    public void A_stream_that_is_disposed_gets_no_more_events_and_is_completed()
    {
        var stream = _hub.Subscribe();

        stream.Dispose();
        _ = _hub.Pause("s-1", Widgets, null, null, _ => true);

        Assert.False(stream.Events.TryRead(out _));
        Assert.True(stream.Events.Completion.IsCompletedSuccessfully);
    }

    [Fact]
    public void A_pause_denies_with_its_reason_when_it_has_one_and_holds_until_its_end_and_without_one_for_ever()
    {
        var now = _time.Now;
        var open = new PausedSession("s-1", null, null);
        var blank = new PausedSession("s-1", "  ", now.AddMinutes(1));
        var reasoned = new PausedSession("s-1", "incident 42", now.AddMinutes(1));

        Assert.EndsWith("work around it.", open.DenyReason(), StringComparison.Ordinal);
        Assert.EndsWith("work around it.", blank.DenyReason(), StringComparison.Ordinal);
        Assert.EndsWith(" Reason: incident 42", reasoned.DenyReason(), StringComparison.Ordinal);
        Assert.True(open.IsActive(now.AddYears(10)));
        Assert.True(reasoned.IsActive(now));
        Assert.False(reasoned.IsActive(now.AddMinutes(1)));
        Assert.False(reasoned.IsActive(now.AddMinutes(2)));
    }
}
