namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The pauses the resident process knows. Every change is written to the state folder at once, whole and atomically, so a hook that
/// evaluates in-process reads the same pauses from disk with no network and no running process. What is in memory answers the
/// decisions of the resident process itself.
/// </summary>
internal sealed class PauseBoard
{
    private readonly Lock _gate = new();
    private readonly ResidentState _state;
    private readonly TimeProvider _time;
    private List<PausedSession> _pauses;

    /// <summary>Starts with what the state folder holds, so pauses survive a restart of the process. A pause file that cannot be read
    /// starts empty here; hooks keep treating every session as paused until the next write replaces it.</summary>
    public PauseBoard(ResidentState state, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(state);
        _state = state;
        _time = time ?? TimeProvider.System;
        try
        {
            _pauses = [.. state.ReadPauses()];
        }
        catch (InvalidDataException)
        {
            _pauses = [];
        }
    }

    /// <summary>The pause that names <paramref name="session"/> and still holds, or <see langword="null"/>.</summary>
    public PausedSession? Find(string session)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            return _pauses.Find(p => string.Equals(p.Session, session, StringComparison.Ordinal) && p.IsActive(now));
        }
    }

    /// <summary>The pauses that still hold.</summary>
    public IReadOnlyList<PausedSession> Current()
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            return [.. _pauses.Where(p => p.IsActive(now))];
        }
    }

    /// <summary>Replaces every pause with <paramref name="pauses"/>: what a snapshot of the server says.</summary>
    public void Replace(IEnumerable<PausedSession> pauses)
    {
        ArgumentNullException.ThrowIfNull(pauses);
        Change(list =>
        {
            list.Clear();
            list.AddRange(pauses.Where(p => p?.Session is not null));
        });
    }

    /// <summary>Adds a pause, or replaces the pause of the same session.</summary>
    public void Add(PausedSession pause)
    {
        ArgumentNullException.ThrowIfNull(pause);
        Change(list =>
        {
            list.RemoveAll(p => string.Equals(p.Session, pause.Session, StringComparison.Ordinal));
            list.Add(pause);
        });
    }

    /// <summary>Lifts the pause of <paramref name="session"/>.</summary>
    public void Remove(string session) =>
        Change(list => list.RemoveAll(p => string.Equals(p.Session, session, StringComparison.Ordinal)));

    // Memory first, so the process answers at once; the file follows under the same lock, so the two never disagree about the order.
    private void Change(Action<List<PausedSession>> change)
    {
        lock (_gate)
        {
            change(_pauses);
            var now = _time.GetUtcNow();
            _pauses.RemoveAll(p => !p.IsActive(now));
            _state.WritePauses(_pauses);
        }
    }
}
