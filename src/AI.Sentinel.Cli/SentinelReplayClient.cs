using Microsoft.Extensions.AI;

namespace AI.Sentinel.Cli;

/// <summary>
/// An <see cref="IChatClient"/> that returns pre-recorded assistant messages as responses,
/// for offline replay of saved conversations through the detector pipeline.
/// </summary>
public sealed class SentinelReplayClient(IReadOnlyList<ChatMessage> recordedResponses) : IChatClient
{
    private int _index;

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var next = Interlocked.Increment(ref _index) - 1;
        if (next >= recordedResponses.Count)
            throw new InvalidOperationException(
                $"Replay exhausted: {recordedResponses.Count} responses consumed.");
        return Task.FromResult(new ChatResponse([recordedResponses[next]]));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
        => throw new NotSupportedException("Use non-streaming GetResponseAsync for replay.");

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
