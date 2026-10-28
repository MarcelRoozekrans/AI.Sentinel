using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using ZeroAlloc.Results.Extensions;

namespace AI.Sentinel;

/// <summary>
/// The <see cref="IChatClient"/> that <c>UseAISentinel</c> inserts into a chat pipeline. It runs every call
/// through a <see cref="SentinelPipeline"/> and throws when that pipeline returns an error.
/// </summary>
public sealed class SentinelChatClient : DelegatingChatClient
{
    private readonly SentinelPipeline _sentinel;

    internal SentinelChatClient(
        IChatClient innerClient,
        IDetectionPipeline pipeline,
        IAuditStore auditStore,
        InterventionEngine interventionEngine,
        SentinelOptions options,
        IAlertSink? alertSink = null,
        IEnumerable<IAuditForwarder>? forwarders = null,
        string? pipelineName = null)
        : this(new SentinelPipeline(
            innerClient, pipeline, auditStore, interventionEngine, options, alertSink, forwarders, pipelineName))
    {
    }

    /// <summary>Runs every call through <paramref name="sentinel"/>, which forwards to its inner client.</summary>
    internal SentinelChatClient(SentinelPipeline sentinel)
        : base(sentinel.InnerClient)
    {
        _sentinel = sentinel;
    }

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
