using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;

namespace AI.Sentinel;

public sealed class SentinelChatClient(
    IChatClient innerClient,
    DetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options) : DelegatingChatClient(innerClient)
{
    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        CancellationToken cancellationToken = default)
    {
        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var sessionId = SessionId.New();

        // Scan the prompt
        var promptCtx = new SentinelContext(
            options.DefaultSenderId,
            options.DefaultReceiverId,
            sessionId,
            messageList,
            []);

        var promptResult = await pipeline.RunAsync(promptCtx, cancellationToken);
        await AppendAuditAsync(promptResult, messageList, cancellationToken);
        interventionEngine.Apply(promptResult, sessionId, options.DefaultSenderId, options.DefaultReceiverId);

        // Call the inner client
        var response = await base.GetResponseAsync(messages, chatOptions, cancellationToken);

        // Scan the response
        IReadOnlyList<ChatMessage> responseMessages = (IReadOnlyList<ChatMessage>)response.Messages;
        var responseCtx = new SentinelContext(
            options.DefaultReceiverId,
            options.DefaultSenderId,
            sessionId,
            responseMessages,
            []);

        var responseResult = await pipeline.RunAsync(responseCtx, cancellationToken);
        await AppendAuditAsync(responseResult, responseMessages, cancellationToken);
        interventionEngine.Apply(responseResult, sessionId, options.DefaultReceiverId, options.DefaultSenderId);

        return response;
    }

    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var sessionId = SessionId.New();

        var ctx = new SentinelContext(
            options.DefaultSenderId,
            options.DefaultReceiverId,
            sessionId,
            messageList,
            []);

        var result = await pipeline.RunAsync(ctx, cancellationToken);
        await AppendAuditAsync(result, messageList, cancellationToken);
        interventionEngine.Apply(result, sessionId, options.DefaultSenderId, options.DefaultReceiverId);

        await foreach (var update in base.GetStreamingResponseAsync(messages, chatOptions, cancellationToken))
            yield return update;
    }

    private async Task AppendAuditAsync(
        PipelineResult result,
        IReadOnlyList<ChatMessage> msgs,
        CancellationToken cancellationToken)
    {
        foreach (var detection in result.Detections)
        {
            var content = msgs.LastOrDefault()?.Text ?? "";
            var hash = ComputeHash(content);
            var entry = new AuditEntry(
                Guid.NewGuid().ToString("N"),
                DateTimeOffset.UtcNow,
                hash,
                null,
                detection.Severity,
                detection.DetectorId.ToString(),
                detection.Reason);
            await auditStore.AppendAsync(entry, cancellationToken);
        }
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
