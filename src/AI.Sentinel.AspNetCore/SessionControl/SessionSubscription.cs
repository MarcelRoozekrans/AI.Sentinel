using System.Threading.Channels;
using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.AspNetCore.SessionControl;

/// <summary>One open event stream: the snapshot it starts with and the events after it. Disposing it unsubscribes.</summary>
internal sealed class SessionSubscription(SessionSnapshot snapshot, ChannelReader<SseFrame> events, Action unsubscribe) : IDisposable
{
    public SessionSnapshot Snapshot { get; } = snapshot;

    public ChannelReader<SseFrame> Events { get; } = events;

    public void Dispose() => unsubscribe();
}
