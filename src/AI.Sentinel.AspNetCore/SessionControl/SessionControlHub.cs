using System.Text.Json;
using System.Threading.Channels;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.AspNetCore.SessionControl;

/// <summary>
/// The pauses in force and the open event streams. A pause or release is applied and then sent to every stream; a configuration that
/// comes into force is announced on them too. A stream that falls too far behind is closed instead of losing an event, because a
/// resident process that reconnects starts from a snapshot and so cannot miss a pause. The pauses are kept in memory: they end with the server.
/// </summary>
internal sealed class SessionControlHub : IDisposable
{
    /// <summary>The events a stream may have waiting before it is closed.</summary>
    private const int StreamBacklog = 256;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, HeldPause> _pauses = new(StringComparer.Ordinal);
    private readonly List<Channel<SseFrame>> _streams = [];
    private readonly PolicyFolderLoader _loader;
    private readonly TimeProvider _time;

    public SessionControlHub(PolicyFolderLoader loader, TimeProvider time)
    {
        _loader = loader;
        _time = time;
        loader.Published += OnPublished;
    }

    public void Dispose() => _loader.Published -= OnPublished;

    /// <summary>
    /// Pauses <paramref name="session"/>, or replaces its pause. A pause in force is replaced only when <paramref name="mayReplace"/>
    /// accepts the repository it was placed for; the check and the write happen under one lock, so a pause cannot be swapped between them.
    /// Returns null when the replacement is refused.
    /// </summary>
    public PausedSession? Pause(string session, string repository, string? reason, DateTimeOffset? until, Func<string, bool> mayReplace)
    {
        var pause = new PausedSession(session, reason, until);
        lock (_gate)
        {
            PruneExpired();
            if (_pauses.TryGetValue(session, out var existing) && !mayReplace(existing.Repository))
            {
                return null;
            }

            _pauses[session] = new HeldPause(pause, repository);
            Publish(SessionEventNames.Pause, JsonSerializer.Serialize(pause, SessionEventJsonContext.Default.PausedSession));
        }

        return pause;
    }

    /// <summary>The pause of <paramref name="session"/> when it is in force.</summary>
    public HeldPause? Find(string session)
    {
        lock (_gate)
        {
            PruneExpired();
            return _pauses.TryGetValue(session, out var held) ? held : null;
        }
    }

    /// <summary>Lifts <paramref name="held"/>, the pause the caller was authorized for; false when the session no longer holds that pause.</summary>
    public bool Release(HeldPause held)
    {
        lock (_gate)
        {
            if (!_pauses.TryGetValue(held.Pause.Session, out var current) || !ReferenceEquals(current, held))
            {
                return false;
            }

            _ = _pauses.Remove(held.Pause.Session);
            Publish(SessionEventNames.Release, JsonSerializer.Serialize(new ReleasedSession(held.Pause.Session), SessionEventJsonContext.Default.ReleasedSession));
            return true;
        }
    }

    /// <summary>The pauses in force.</summary>
    public IReadOnlyList<HeldPause> List()
    {
        lock (_gate)
        {
            PruneExpired();
            return [.. _pauses.Values];
        }
    }

    // Called under the gate. A timed pause that has lapsed is dropped, so the table holds only what is in force.
    private void PruneExpired()
    {
        var now = _time.GetUtcNow();
        List<string>? lapsed = null;
        foreach (var (session, held) in _pauses)
        {
            if (!held.Pause.IsActive(now))
            {
                (lapsed ??= []).Add(session);
            }
        }

        if (lapsed is null)
        {
            return;
        }

        foreach (var session in lapsed)
        {
            _ = _pauses.Remove(session);
        }
    }

    /// <summary>Opens a stream. The snapshot and the subscription are made together, so no event falls between them.</summary>
    public SessionSubscription Subscribe()
    {
        var channel = Channel.CreateBounded<SseFrame>(new BoundedChannelOptions(StreamBacklog) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
        lock (_gate)
        {
            PruneExpired();
            _streams.Add(channel);
            var snapshot = new SessionSnapshot(_loader.Current?.Version, [.. _pauses.Values.Select(h => h.Pause)]);
            return new SessionSubscription(snapshot, channel.Reader, () =>
            {
                lock (_gate)
                {
                    _streams.Remove(channel);
                }

                _ = channel.Writer.TryComplete();
            });
        }
    }

    private void OnPublished(object? sender, ConfigurationPublishedEventArgs e)
    {
        lock (_gate)
        {
            Publish(SessionEventNames.Configuration, JsonSerializer.Serialize(new ConfigurationAnnounced(e.Configuration.Version), SessionEventJsonContext.Default.ConfigurationAnnounced));
        }
    }

    // Called under the gate. A stream whose backlog is full is closed, and its client reconnects to a fresh snapshot.
    private void Publish(string name, string data)
    {
        var frame = new SseFrame(name, data);
        for (var i = _streams.Count - 1; i >= 0; i--)
        {
            if (!_streams[i].Writer.TryWrite(frame))
            {
                _ = _streams[i].Writer.TryComplete(new IOException("the stream fell behind"));
                _streams.RemoveAt(i);
            }
        }
    }
}
