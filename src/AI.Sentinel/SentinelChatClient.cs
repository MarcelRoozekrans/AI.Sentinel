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

        var ctx = new SentinelContext(
            options.DefaultSenderId,
            options.DefaultReceiverId,
            sessionId,
            messageList,
            []);

        var result = await pipeline.RunAsync(ctx, cancellationToken);

        // Audit all non-clean detections
        foreach (var detection in result.Detections)
        {
            var content = messageList.LastOrDefault()?.Text ?? "";
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

        interventionEngine.Apply(result, sessionId, options.DefaultSenderId, options.DefaultReceiverId);

        return await base.GetResponseAsync(messages, chatOptions, cancellationToken);
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

        foreach (var detection in result.Detections)
        {
            var content = messageList.LastOrDefault()?.Text ?? "";
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

        interventionEngine.Apply(result, sessionId, options.DefaultSenderId, options.DefaultReceiverId);

        await foreach (var update in base.GetStreamingResponseAsync(messages, chatOptions, cancellationToken))
            yield return update;
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
