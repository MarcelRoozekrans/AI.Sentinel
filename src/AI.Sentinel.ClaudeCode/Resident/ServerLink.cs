using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The resident process's connection to the server: a Server-Sent Events stream that carries pauses, releases and announcements of a
/// published configuration. A pause is applied the moment it arrives, to the pause board and the state folder. The stream reconnects
/// with backoff and jitter, and every connection starts with a snapshot, so a pause or a release that came while it was down is applied
/// then. It runs in the background of the process and never takes the lock a decision is made under, so it can never block a hook.
/// </summary>
internal sealed class ServerLink(
    HttpClient http, Uri server, PauseBoard board, ProfileRefresher refresher, ServerLinkTiming timing, TimeProvider time, Action<string>? log = null)
{
    private int _snapshots;
    private bool _snapshotDelivered;

    /// <summary>Runs until <paramref name="ct"/> ends, with the profile refresher beside it.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        var refreshing = Task.Run(() => refresher.RunAsync(ct), CancellationToken.None);
        try
        {
            await ConnectLoopAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The process is stopping.
        }
        finally
        {
            try
            {
                await refreshing.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Stopped with the link.
            }
        }
    }

    private async Task ConnectLoopAsync(CancellationToken ct)
    {
        var wait = timing.ReconnectInitial;
        while (!ct.IsCancellationRequested)
        {
            _snapshotDelivered = false;
            try
            {
                await ConsumeAsync(ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is HttpRequestException or IOException or InvalidDataException or JsonException or SignIn.SignInRequiredException
                or UnauthorizedAccessException || (e is OperationCanceledException && !ct.IsCancellationRequested))
            {
                log?.Invoke($"the connection to the server ended ({e.GetType().Name}); reconnecting");
            }

            // A connection that delivered its snapshot worked, however it ended; one that failed before it keeps the growing backoff.
            if (_snapshotDelivered)
            {
                wait = timing.ReconnectInitial;
            }

            await Task.Delay(Jitter(wait), time, ct).ConfigureAwait(false);
            wait = wait * 2 > timing.ReconnectMax ? timing.ReconnectMax : wait * 2;
        }
    }

    private async Task ConnectedAsync(Stream body, CancellationToken ct)
    {
        await foreach (var message in SseReader.ReadAsync(body, timing.Stall, ct).ConfigureAwait(false))
        {
            Handle(message);
        }
    }

    private async Task ConsumeAsync(CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(server, SessionEventNames.StreamPath));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using var body = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await ConnectedAsync(body, ct).ConfigureAwait(false);
    }

    private void Handle(SseMessage message)
    {
        switch (message.Event)
        {
            case SessionEventNames.Snapshot:
                var snapshot = JsonSerializer.Deserialize(message.Data!, SessionEventJsonContext.Default.SessionSnapshot)
                    ?? throw new InvalidDataException("an empty snapshot");
                board.Replace(snapshot.Pauses ?? []);
                _snapshotDelivered = true;
                if (_snapshots++ == 0)
                {
                    // The first connection: the fetch at start covers it unless a newer configuration is already in force.
                    refresher.Announce(snapshot.ConfigurationVersion ?? 0);
                }
                else
                {
                    // A configuration that came into force while the stream was down is fetched now, whatever the snapshot says.
                    refresher.Wake();
                }

                break;
            case SessionEventNames.Pause:
                board.Add(JsonSerializer.Deserialize(message.Data!, SessionEventJsonContext.Default.PausedSession) is { Session: not null } pause
                    ? pause
                    : throw new InvalidDataException("a pause names no session"));
                break;
            case SessionEventNames.Release:
                board.Remove(JsonSerializer.Deserialize(message.Data!, SessionEventJsonContext.Default.ReleasedSession)?.Session
                    ?? throw new InvalidDataException("a release names no session"));
                break;
            case SessionEventNames.Configuration:
                refresher.Announce((JsonSerializer.Deserialize(message.Data!, SessionEventJsonContext.Default.ConfigurationAnnounced)
                    ?? throw new InvalidDataException("an empty announcement")).Version);
                break;
            default:
                // A heartbeat, or an event of a later server: ignored.
                break;
        }
    }

    private static TimeSpan Jitter(TimeSpan wait) => wait * (RandomNumberGenerator.GetInt32(750, 1251) / 1000.0);
}
