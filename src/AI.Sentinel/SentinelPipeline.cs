using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using ZeroAlloc.Results;

namespace AI.Sentinel;

public sealed class SentinelPipeline(
    IChatClient innerClient,
    DetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options)
{
    public async ValueTask<Result<ChatResponse, SentinelError>> GetResponseResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var sessionId = SessionId.New();

        var promptError = await ScanAsync(messageList, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct).ConfigureAwait(false);
        if (promptError is not null)
            return Result<ChatResponse, SentinelError>.Failure(promptError);

        ChatResponse response;
        try
        {
            response = await innerClient.GetResponseAsync(messageList, chatOptions, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return Result<ChatResponse, SentinelError>.Failure(
                new SentinelError.PipelineFailure("Inner client failed.", ex));
        }

        IReadOnlyList<ChatMessage> responseMessages =
            response.Messages as IReadOnlyList<ChatMessage> ?? response.Messages.ToList();
        var responseError = await ScanAsync(responseMessages, sessionId,
            options.DefaultReceiverId, options.DefaultSenderId, ct).ConfigureAwait(false);
        if (responseError is not null)
            return Result<ChatResponse, SentinelError>.Failure(responseError);

        return Result<ChatResponse, SentinelError>.Success(response);
    }

    private async ValueTask<SentinelError?> ScanAsync(
        IReadOnlyList<ChatMessage> msgs,
        SessionId sessionId,
        AgentId sender,
        AgentId receiver,
        CancellationToken ct)
    {
        var ctx = new SentinelContext(sender, receiver, sessionId, msgs, []);
        var pipelineResult = await pipeline.RunAsync(ctx, ct).ConfigureAwait(false);
        await AppendAuditAsync(pipelineResult, msgs, ct).ConfigureAwait(false);

        if (pipelineResult.IsClean) return null;

        var action = options.ActionFor(pipelineResult.MaxSeverity);

        try
        {
            interventionEngine.Apply(pipelineResult, sessionId, sender, receiver);
        }
        catch (SentinelException ex)
        {
            // Quarantine: convert throw to Result instead of re-throwing.
            // Use the PipelineResult carried by the exception — it has the real detections.
            var top = ex.PipelineResult.Detections.FirstOrDefault()
                ?? pipelineResult.Detections.First();
            return new SentinelError.ThreatDetected(top, action);
        }

        return null;
    }

    private async Task AppendAuditAsync(
        PipelineResult result,
        IReadOnlyList<ChatMessage> msgs,
        CancellationToken ct)
    {
        var content = msgs.LastOrDefault()?.Text ?? "";
        var hash = ComputeHash(content);
        foreach (var detection in result.Detections)
        {
            var entry = new AuditEntry(
                Guid.NewGuid().ToString("N"),
                DateTimeOffset.UtcNow,
                hash, null,
                detection.Severity,
                detection.DetectorId.ToString(),
                detection.Reason);
            await auditStore.AppendAsync(entry, ct).ConfigureAwait(false);
        }
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
