using Microsoft.Extensions.AI;

namespace AI.Sentinel.Cli;

/// <summary>
/// An <see cref="IChatClient"/> that returns pre-recorded assistant messages as responses,
/// for offline replay of saved conversations through the detector pipeline.
/// </summary>
/// <remarks>
/// Not thread-safe. Callers must serialize <see cref="GetResponseAsync"/> invocations
/// externally — the class maintains an internal position counter, and concurrent calls
/// would produce unpredictable response ordering. This is consistent with the replay
/// use case: responses are indexed to their corresponding prompts, so ordering must
/// match the recorded conversation.
/// </remarks>
public sealed class SentinelReplayClient(IReadOnlyList<ChatMessage> recordedResponses) : IChatClient
{
    private int _index;

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (_index >= recordedResponses.Count)
            throw new InvalidOperationException(
                $"Replay exhausted: {recordedResponses.Count} responses consumed.");
        var next = _index++;
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
