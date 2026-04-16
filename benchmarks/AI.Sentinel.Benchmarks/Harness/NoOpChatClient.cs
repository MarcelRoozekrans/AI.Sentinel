using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks.Harness;

/// <summary>
/// Returns a fixed empty response synchronously. Used as the inner IChatClient
/// in benchmarks so we measure only AI.Sentinel overhead, not network latency.
/// </summary>
internal sealed class NoOpChatClient : IChatClient
{
    public static readonly NoOpChatClient Instance = new();

    private static readonly ChatResponse EmptyResponse =
        new(new ChatMessage(ChatRole.Assistant, "ok"));

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(EmptyResponse);

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        yield break;
    }

    public ChatClientMetadata Metadata => new("noop", null, null);

    public object? GetService(Type serviceType, object? key = null) => null;

    public void Dispose() { }
}
