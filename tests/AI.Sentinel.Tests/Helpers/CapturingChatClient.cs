using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>An <see cref="IChatClient"/> that records the messages it is sent and answers with fixed text, or throws.</summary>
internal sealed class CapturingChatClient(List<ChatMessage> captured, string responseText, Exception? failure = null) : IChatClient
{
    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        captured.AddRange(messages);
        if (failure is not null) throw failure;
        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, responseText)));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        throw new NotSupportedException("Streaming not needed in this test double.");
    }

    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
