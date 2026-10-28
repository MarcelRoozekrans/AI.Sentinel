using Microsoft.Extensions.AI;

namespace AI.Sentinel.Screening;

/// <summary>The inner client of a screening pipeline: screening never calls a model.</summary>
internal sealed class NeverCalledChatClient : IChatClient
{
    public static readonly NeverCalledChatClient Instance = new();

    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("Screening never calls the model.");

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("Screening never calls the model.");

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose()
    {
    }
}
