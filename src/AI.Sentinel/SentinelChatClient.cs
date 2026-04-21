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
    IDetectionPipeline pipeline,
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

    private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var result = await _sentinel
            .GetStreamingResultAsync(messages, chatOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result.IsFailure)
            throw result.Error.ToException();
        foreach (var update in result.Value)
            yield return update;
    }
}
