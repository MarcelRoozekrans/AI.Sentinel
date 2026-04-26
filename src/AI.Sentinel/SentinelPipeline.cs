using System.Collections.Concurrent;
using System.Diagnostics;
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
    private static readonly ActivitySource _activitySource = new("ai.sentinel");
    private readonly ConcurrentDictionary<string, RateLimiterEntry> _rateLimiters = new(StringComparer.Ordinal);
    private int _rateLimiterWriteCount;

    // EmbeddingGenerator not set — all SemanticDetectorBase subclasses return Clean.
    // Set SentinelOptions.EmbeddingGenerator to enable language-agnostic detection.

    private sealed class RateLimiterEntry(RateLimiter limiter)
    {
        public RateLimiter Limiter { get; } = limiter;
        public long LastUsedMs = Environment.TickCount64;
    }

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
            response = await innerClient
                .GetResponseAsync(ApplyHardening(messageList), chatOptions, ct)
                .ConfigureAwait(false);
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
                .GetStreamingResponseAsync(ApplyHardening(messageList), chatOptions, ct)
                .ConfigureAwait(false))
                buffer.Add(update);
        }
        catch (Exception ex)
        {
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(
                new SentinelError.PipelineFailure("Inner client streaming failed.", ex));
        }

        var sb = new StringBuilder();
        for (var i = 0; i < buffer.Count; i++) sb.Append(buffer[i].Text);
        var responseText = sb.ToString();
        IReadOnlyList<ChatMessage> responseMessages =
            [new ChatMessage(ChatRole.Assistant, responseText)];

        var responseError = await ScanAsync(responseMessages, sessionId,
            options.DefaultReceiverId, options.DefaultSenderId, ct).ConfigureAwait(false);
        if (responseError is not null)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(responseError);

        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Success(buffer);
    }

    /// <summary>Runs detection against <paramref name="messages"/> without invoking the inner chat client.
    /// Useful for hook adapters that scan caller-supplied prompts or tool payloads where there is no LLM response.</summary>
    /// <remarks>
    /// Rate-limit check fires first; on exceeded quota the method returns <see cref="SentinelError.RateLimitExceeded"/>.
    /// Otherwise runs a single detection pass and returns <see langword="null"/> on clean,
    /// <see cref="SentinelError.ThreatDetected"/> on detection.
    /// </remarks>
    public async ValueTask<SentinelError?> ScanMessagesAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        CancellationToken ct = default)
    {
        var rateError = CheckRateLimit(chatOptions);
        if (rateError is not null) return rateError;

        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var sessionId = SessionId.New();
        return await ScanAsync(messageList, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct).ConfigureAwait(false);
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
            SentinelMetrics.Threats.Add(1, tags);
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

    /// <summary>
    /// Returns a copy of <paramref name="messages"/> with the configured <see cref="SentinelOptions.SystemPrefix"/>
    /// prepended/merged into the leading system message. If <c>SystemPrefix</c> is null or empty, the original
    /// list is returned unchanged. Detection always runs on the unmodified <paramref name="messages"/> — this
    /// substitution applies only at the forward point to the inner <see cref="IChatClient"/>.
    /// </summary>
    private IReadOnlyList<ChatMessage> ApplyHardening(IReadOnlyList<ChatMessage> messages)
    {
        var prefix = options.SystemPrefix;
        if (string.IsNullOrWhiteSpace(prefix))
            return messages;

        var copy = new List<ChatMessage>(messages.Count + 1);
        copy.AddRange(messages);
        if (copy.Count > 0 && copy[0].Role == ChatRole.System)
        {
            var original = copy[0].Text ?? string.Empty;
            copy[0] = new ChatMessage(ChatRole.System, $"{prefix}\n\n{original}");
        }
        else
        {
            copy.Insert(0, new ChatMessage(ChatRole.System, prefix));
        }
        return copy;
    }

    private SentinelError? CheckRateLimit(ChatOptions? chatOptions)
    {
        if (options.MaxCallsPerSecond is not int maxRps) return null;

        var sessionKey = chatOptions?.AdditionalProperties
            ?.GetValueOrDefault("sentinel.session_id") as string ?? "__global__";
        var burst = options.BurstSize ?? maxRps;
        var entry = _rateLimiters.GetOrAdd(sessionKey,
            _ => new RateLimiterEntry(new RateLimiter(maxRps, burst, RateLimitScope.Instance)));
        entry.LastUsedMs = Environment.TickCount64;

        SweepIdleLimiters();

        if (entry.Limiter.TryAcquire()) return null;

        SentinelMetrics.RateLimited.Add(1, new TagList { { "session", sessionKey } });
        return new SentinelError.RateLimitExceeded(sessionKey);
    }

    private void SweepIdleLimiters()
    {
        if ((Interlocked.Increment(ref _rateLimiterWriteCount) & 255) != 0) return;
        var idleThreshold = Environment.TickCount64 - (long)options.SessionIdleTimeout.TotalMilliseconds;
        foreach (var kvp in _rateLimiters)
            if (kvp.Value.LastUsedMs < idleThreshold)
                _rateLimiters.TryRemove(kvp);
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
