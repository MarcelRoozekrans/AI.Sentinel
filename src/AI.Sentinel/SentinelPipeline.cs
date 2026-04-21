using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using ZeroAlloc.Resilience;
using ZeroAlloc.Results;

namespace AI.Sentinel;

/// <summary>Wraps an <see cref="IChatClient"/> with threat detection, intervention, and auditing for both prompt and response messages.</summary>
public sealed class SentinelPipeline(
    IChatClient innerClient,
    IDetectionPipeline pipeline,
    IAuditStore auditStore,
    InterventionEngine interventionEngine,
    SentinelOptions options,
    IAlertSink? alertSink = null)
{
    private static readonly Meter _meter = new("ai.sentinel");
    private static readonly Counter<long> _threats = _meter.CreateCounter<long>("sentinel.threats");
    private static readonly ActivitySource _activitySource = new("ai.sentinel");
    private static readonly Counter<long> _rateLimited =
        _meter.CreateCounter<long>("sentinel.rate_limit.exceeded");
    private readonly ConcurrentDictionary<string, RateLimiter> _rateLimiters = new(StringComparer.Ordinal);

    /// <summary>Scans the prompt and response for threats and returns the chat response on success, or a <see cref="SentinelError"/> if a threat is detected or the inner client fails.</summary>
    /// <param name="messages">The conversation messages to send to the inner client.</param>
    /// <param name="chatOptions">Optional chat options forwarded to the inner client.</param>
    /// <param name="ct">Cancellation token for the operation.</param>
    /// <returns>A successful <see cref="ChatResponse"/> when no threats are found, or a <see cref="SentinelError.ThreatDetected"/> / <see cref="SentinelError.PipelineFailure"/> on failure.</returns>
    public async ValueTask<Result<ChatResponse, SentinelError>> GetResponseResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var rateError = CheckRateLimit(chatOptions);
        if (rateError is not null)
            return Result<ChatResponse, SentinelError>.Failure(rateError);

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

    /// <summary>Buffers the full inner streaming response, scans both prompt and response,
    /// and returns the buffer on success or a <see cref="SentinelError"/> on failure.</summary>
    /// <remarks>
    /// Buffering is intentional — it ensures a quarantined response never reaches the caller.
    /// Time-to-first-token equals total LLM response latency on this path.
    /// </remarks>
    public async ValueTask<Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>> GetStreamingResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var rateError = CheckRateLimit(chatOptions);
        if (rateError is not null)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(rateError);

        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var sessionId = SessionId.New();

        var promptError = await ScanAsync(messageList, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct).ConfigureAwait(false);
        if (promptError is not null)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(promptError);

        var buffer = new List<ChatResponseUpdate>();
        try
        {
            await foreach (var update in innerClient
                .GetStreamingResponseAsync(messageList, chatOptions, ct)
                .ConfigureAwait(false))
                buffer.Add(update);
        }
        catch (Exception ex)
        {
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(
                new SentinelError.PipelineFailure("Inner client streaming failed.", ex));
        }

        var responseText = string.Concat(buffer.Select(u => u.Text ?? ""));
        IReadOnlyList<ChatMessage> responseMessages =
            [new ChatMessage(ChatRole.Assistant, responseText)];

        var responseError = await ScanAsync(responseMessages, sessionId,
            options.DefaultReceiverId, options.DefaultSenderId, ct).ConfigureAwait(false);
        if (responseError is not null)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(responseError);

        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Success(buffer);
    }

    private async ValueTask<SentinelError?> ScanAsync(
        IReadOnlyList<ChatMessage> msgs,
        SessionId sessionId,
        AgentId sender,
        AgentId receiver,
        CancellationToken ct)
    {
        var ctx = new SentinelContext(sender, receiver, sessionId, msgs, []);
        using var scanActivity = _activitySource.StartActivity("sentinel.scan");
        var pipelineResult = await pipeline.RunAsync(ctx, ct).ConfigureAwait(false);
        await AppendAuditAsync(pipelineResult, msgs, ct).ConfigureAwait(false);

        scanActivity?.SetTag("sentinel.severity", pipelineResult.MaxSeverity.ToString());
        scanActivity?.SetTag("sentinel.is_clean", pipelineResult.IsClean);
        scanActivity?.SetTag("sentinel.threat_count", pipelineResult.Detections.Count);
        var topDetector = pipelineResult.Detections.MaxBy(d => d.Severity);
        if (topDetector is not null)
            scanActivity?.SetTag("sentinel.top_detector", topDetector.DetectorId.ToString());

        if (pipelineResult.IsClean) return null;

        foreach (var d in pipelineResult.Detections)
        {
            var tags = new TagList
            {
                { "severity", d.Severity.ToString() },
                { "detector", d.DetectorId.ToString() }
            };
            _threats.Add(1, tags);
        }

        var action = options.ActionFor(pipelineResult.MaxSeverity);

        if ((action == SentinelAction.Quarantine || action == SentinelAction.Alert) && alertSink is not null)
        {
            var top = pipelineResult.Detections.MaxBy(d => d.Severity)
                ?? DetectionResult.Clean(new DetectorId("unknown"));
            // Fire-and-forget: alert failures must never propagate to the caller.
            // Implementations of IAlertSink are expected to swallow their own exceptions.
            _ = alertSink.SendAsync(new SentinelError.ThreatDetected(top, action, sessionId), CancellationToken.None).AsTask();
        }

        try
        {
            interventionEngine.Apply(pipelineResult, sessionId, sender, receiver);
        }
        catch (SentinelException ex)
        {
            // Quarantine: convert throw to Result instead of re-throwing.
            // Use the PipelineResult carried by the exception — it has the real detections.
            var top = ex.PipelineResult.Detections.MaxBy(d => d.Severity)
                ?? pipelineResult.Detections.MaxBy(d => d.Severity)
                ?? DetectionResult.Clean(new DetectorId("unknown"));
            return new SentinelError.ThreatDetected(top, action, sessionId);
        }

        return null;
    }

    private SentinelError? CheckRateLimit(ChatOptions? chatOptions)
    {
        if (options.MaxCallsPerSecond is not int maxRps) return null;

        var sessionKey = chatOptions?.AdditionalProperties
            ?.GetValueOrDefault("sentinel.session_id") as string ?? "__global__";
        var burst = options.BurstSize ?? maxRps;
        var limiter = _rateLimiters.GetOrAdd(sessionKey,
            _ => new RateLimiter(maxRps, burst, RateLimitScope.Instance));

        if (limiter.TryAcquire()) return null;

        _rateLimited.Add(1, new TagList { { "session", sessionKey } });
        return new SentinelError.RateLimitExceeded(sessionKey);
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
