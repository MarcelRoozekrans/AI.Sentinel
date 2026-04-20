using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using ZeroAlloc.Results.Extensions;

namespace AI.Sentinel;

public sealed class SentinelChatClient(
    IChatClient innerClient,
    DetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options,
    IAlertSink? alertSink = null) : DelegatingChatClient(innerClient)
{
    private readonly SentinelPipeline _sentinel = new(innerClient, pipeline, auditStore, interventionEngine, options, alertSink);

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        CancellationToken cancellationToken = default)
    {
        var result = await _sentinel.GetResponseResultAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false);
        return result.Match(ok => ok, err => throw err.ToException());
    }

    public override IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        CancellationToken cancellationToken = default)
        => StreamAsync(messages, chatOptions, cancellationToken);

    // Streaming is a pass-through with no sentinel scan — scanning streamed responses
    // requires SentinelPipeline.GetStreamingResultAsync, which is a future backlog item.
    private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var update in base.GetStreamingResponseAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false))
            yield return update;
    }
}
