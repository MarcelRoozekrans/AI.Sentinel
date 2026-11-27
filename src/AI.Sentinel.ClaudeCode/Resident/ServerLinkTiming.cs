namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The waits of the link to the server. A test shortens them; the defaults are what a PC runs with.</summary>
/// <param name="ReconnectInitial">The wait before the first reconnect; it doubles up to <paramref name="ReconnectMax"/> and starts over after a connection that worked.</param>
/// <param name="ReconnectMax">The longest wait between two connection attempts.</param>
/// <param name="Stall">A stream that sends nothing, not even a heartbeat, for this long is dead and is reconnected.</param>
/// <param name="FetchBackoffInitial">The wait before a failed fetch of the profiles is tried again; it doubles up to <paramref name="FetchBackoffMax"/>.</param>
/// <param name="FetchBackoffMax">The longest wait between two attempts after a failure.</param>
/// <param name="MinFetchGap">Profiles are fetched on a timer at least this long after the last fetch that worked, so a profile that
/// expires soon cannot make the process fetch in a loop. An announcement or a reconnect does not wait for it.</param>
/// <param name="RefreshLead">How long before a profile expires it is fetched again, or half its lifetime when that is shorter.</param>
internal sealed record ServerLinkTiming(
    TimeSpan ReconnectInitial, TimeSpan ReconnectMax, TimeSpan Stall,
    TimeSpan FetchBackoffInitial, TimeSpan FetchBackoffMax, TimeSpan MinFetchGap, TimeSpan RefreshLead)
{
    public static readonly ServerLinkTiming Default = new(
        TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60),
        TimeSpan.FromSeconds(2), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5), TimeSpan.FromDays(1));

    /// <summary>When a profile is fetched again: <see cref="RefreshLead"/> before it expires, or halfway through a lifetime that is
    /// shorter than twice that. A point in the past means at once.</summary>
    public DateTimeOffset RefreshAt(DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        var lifetime = expiresAt - issuedAt;
        var lead = lifetime / 2 < RefreshLead ? lifetime / 2 : RefreshLead;
        return expiresAt - lead;
    }
}
