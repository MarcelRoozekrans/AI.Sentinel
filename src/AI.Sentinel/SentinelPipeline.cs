using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Redaction;
using ZeroAlloc.Resilience;
using ZeroAlloc.Results;

namespace AI.Sentinel;

/// <summary>Wraps an <see cref="IChatClient"/> with threat detection, intervention, and auditing for both prompt and response messages.</summary>
public sealed class SentinelPipeline
{
    private static readonly ActivitySource _activitySource = new("ai.sentinel");
    private readonly ConcurrentDictionary<string, RateLimiterEntry> _rateLimiters = new(StringComparer.Ordinal);
    private readonly IChatClient innerClient;
    private readonly IDetectionPipeline pipeline;
    private readonly IAuditStore auditStore;
    private readonly InterventionEngine interventionEngine;
    private readonly SentinelOptions options;
    private readonly IAlertSink? alertSink;
    private readonly IAuditForwarder[] _forwarders;
    private int _rateLimiterWriteCount;

    /// <summary>Creates the pipeline.</summary>
    /// <param name="innerClient">The underlying <see cref="IChatClient"/> the pipeline forwards sanitized requests to.</param>
    /// <param name="pipeline">Detection pipeline that scans prompt and response messages.</param>
    /// <param name="auditStore">Synchronous audit store that receives every audit entry on the hot path.</param>
    /// <param name="interventionEngine">Intervention engine that applies the configured action when threats are detected.</param>
    /// <param name="options">Sentinel configuration (rate limits, thresholds, hardening prefix, etc.).</param>
    /// <param name="alertSink">Optional alert sink invoked fire-and-forget when an action escalates to <c>Quarantine</c> or <c>Alert</c>.</param>
    /// <param name="forwarders">Optional audit forwarders that mirror every audit entry to external systems fire-and-forget. Default empty.</param>
    public SentinelPipeline(
        IChatClient innerClient,
        IDetectionPipeline pipeline,
        IAuditStore auditStore,
        InterventionEngine interventionEngine,
        SentinelOptions options,
        IAlertSink? alertSink = null,
        IEnumerable<IAuditForwarder>? forwarders = null)
    {
        this.innerClient = innerClient;
        this.pipeline = pipeline;
        this.auditStore = auditStore;
        this.interventionEngine = interventionEngine;
        this.options = options;
        this.alertSink = alertSink;
        _forwarders = AuditForwarding.Snapshot(forwarders);

        // Tool calls the model makes run inside a FunctionInvokingChatClient below this pipeline, if there is
        // one; its hook restores their arguments and redacts their results for the current call.
        RedactionScope.InstallToolHook(innerClient);
    }

    // EmbeddingGenerator not set — all SemanticDetectorBase subclasses return Clean.
    // Set SentinelOptions.EmbeddingGenerator to enable language-agnostic detection.

    private sealed class RateLimiterEntry(RateLimiter limiter)
    {
        public RateLimiter Limiter { get; } = limiter;
        public long LastUsedMs = Environment.TickCount64;
    }

    /// <summary>Redacts and scans the prompt, forwards it, scans the response and restores the redacted
    /// values in it. Returns the chat response on success, or a <see cref="SentinelError"/> if a threat is
    /// detected, redaction fails or the inner client fails.</summary>
    /// <param name="messages">The conversation messages to send to the inner client.</param>
    /// <param name="chatOptions">Optional chat options forwarded to the inner client.</param>
    /// <param name="ct">Cancellation token for the operation.</param>
    /// <returns>A successful <see cref="ChatResponse"/> when no threats are found, or a <see cref="SentinelError.ThreatDetected"/> / <see cref="SentinelError.PipelineFailure"/> on failure.</returns>
    /// <remarks>
    /// Values found by a redacting detector whose effective action is <see cref="SentinelAction.Redact"/>
    /// are replaced by placeholders such as <c>[EMAIL_1]</c> in everything sent to the model: every message,
    /// tool-call arguments and tool results, including the results of tools the model calls during this call.
    /// The other detectors judge the redacted request. The response is scanned as the model produced it and
    /// then, when <see cref="SentinelOptions.RestoreRedactedValues"/> is set, restored. The mapping lives only
    /// for this call. Any failure to redact fails the call closed: nothing is sent unredacted.
    /// </remarks>
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
        // The scope of an enclosing Sentinel call, when this one runs below another.
        var parent = RedactionScope.Current;

        var redactors = pipeline.Redactors;
        var session = redactors.Count > 0 ? new RedactionSession(redactors) : null;
        (messageList, var redactionError) = Redact(session, messageList);
        if (redactionError is not null)
            return Result<ChatResponse, SentinelError>.Failure(redactionError);

        var systemPrompt = SystemPromptOf(messageList);

        // The request holds this call's placeholders and those of any enclosing Sentinel call; none is a value.
        var promptError = await ScanAsync(messageList, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt,
            RedactionScope.ExemptPlaceholders(session, parent)).ConfigureAwait(false);
        if (promptError is not null)
            return Result<ChatResponse, SentinelError>.Failure(promptError);

        // Every placeholder-shaped token in the request the model is about to see. The request was redacted, so
        // none is a raw secret, and the model may legitimately repeat one, including a literal left in history
        // from an earlier round trip.
        var sentPlaceholders = session?.PlaceholdersIn(messageList);

        // Set inside this async method: it flows into the inner clients and never back out to the caller.
        // An enclosing Sentinel's scope becomes the parent, so a tool below both resolves both layers.
        var scope = session is null ? null : new RedactionScope(session, options.RestoreRedactedValues, parent);
        if (scope is not null)
            RedactionScope.Current = scope;

        ChatResponse response;
        try
        {
            response = await innerClient
                .GetResponseAsync(ApplyHardening(messageList), chatOptions, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // The request was sent, so its redactions are compliance evidence even when the call was cancelled.
            await AppendRedactionsAsync(session, sessionId, CancellationToken.None).ConfigureAwait(false);
            return Result<ChatResponse, SentinelError>.Failure(
                new SentinelError.PipelineFailure("Inner client failed.", ex));
        }

        await AppendRedactionsAsync(session, sessionId, ct).ConfigureAwait(false);
        var responseExempt = RedactionScope.ExemptPlaceholders(session, parent, sentPlaceholders);
        return await FinishResponseAsync(response, scope, responseExempt, sessionId, systemPrompt, ct).ConfigureAwait(false);
    }

    /// <summary>Scans the response as the model produced it, so restored values never trigger a response
    /// detection, then restores the redacted values in it.</summary>
    private async ValueTask<Result<ChatResponse, SentinelError>> FinishResponseAsync(
        ChatResponse response, RedactionScope? scope, IReadOnlySet<string>? exemptPlaceholders,
        SessionId sessionId, string? systemPrompt, CancellationToken ct)
    {
        if (scope is { Failed: true })
        {
            return Result<ChatResponse, SentinelError>.Failure(new SentinelError.PipelineFailure(
                "AI.Sentinel could not redact a tool call made during the request; the request was stopped and nothing unredacted was sent."));
        }

        IReadOnlyList<ChatMessage> responseMessages =
            response.Messages as IReadOnlyList<ChatMessage> ?? response.Messages.ToList();
        var responseError = await ScanAsync(responseMessages, sessionId,
            options.DefaultReceiverId, options.DefaultSenderId, ct, systemPrompt, exemptPlaceholders).ConfigureAwait(false);
        if (responseError is not null)
            return Result<ChatResponse, SentinelError>.Failure(responseError);

        if (scope is { Session.HasRedactions: true } && options.RestoreRedactedValues)
        {
            try
            {
                response.Messages = scope.Session.Restore(response.Messages);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return Result<ChatResponse, SentinelError>.Failure(RedactionFailed(ex));
            }
        }

        return Result<ChatResponse, SentinelError>.Success(response);
    }

    private static (IReadOnlyList<ChatMessage> Messages, SentinelError? Error) Redact(
        RedactionSession? session, IReadOnlyList<ChatMessage> messages)
    {
        if (session is null)
            return (messages, null);

        try
        {
            return (session.Redact(messages), null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (messages, RedactionFailed(ex));
        }
    }

    // The exception is not chained: messages and properties of regex, serializer and detector exceptions can
    // carry the text being redacted, for example RegexMatchTimeoutException.Input.
    private static SentinelError.PipelineFailure RedactionFailed(Exception ex) => new(
        $"AI.Sentinel could not redact the request ({ex.GetType().Name}); nothing was sent unredacted.");

    /// <summary>One audit entry per redacting detector, counts only, and one Redact notification.</summary>
    private async Task AppendRedactionsAsync(RedactionSession? session, SessionId sessionId, CancellationToken ct)
    {
        if (session is null)
            return;

        var byDetector = session.CountsByDetector;
        if (byDetector.Count == 0)
            return;

        var byType = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (detectorId, counts) in byDetector)
        {
            var entry = AuditEntryRedactionExtensions.Redaction(detectorId, counts, sessionId.Value);
            await auditStore.AppendAndForwardAsync(entry, _forwarders, ct).ConfigureAwait(false);
            foreach (var (type, count) in counts)
            {
                byType[type] = byType.GetValueOrDefault(type) + count;
            }
        }

        interventionEngine.PublishRedaction(sessionId, byType, AuditEntryRedactionExtensions.Summarize(byType));
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

        var systemPrompt = SystemPromptOf(messageList);

        var promptError = await ScanAsync(messageList, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt).ConfigureAwait(false);
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
            options.DefaultReceiverId, options.DefaultSenderId, ct, systemPrompt).ConfigureAwait(false);
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
    /// When <paramref name="sessionId"/> is supplied the audit entries carry it; otherwise a fresh id is minted per call.
    /// </remarks>
    /// <param name="messages">The messages to scan.</param>
    /// <param name="chatOptions">Options used for the rate-limit check; <see langword="null"/> for none.</param>
    /// <param name="sessionId">The session recorded on the audit entries, as the <see cref="SessionId"/> domain type;
    /// <see langword="null"/> mints a fresh id for this call.</param>
    /// <param name="ct">Cancellation token.</param>
    public async ValueTask<SentinelError?> ScanMessagesAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        SessionId? sessionId = null,
        CancellationToken ct = default)
    {
        var rateError = CheckRateLimit(chatOptions);
        if (rateError is not null) return rateError;

        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        return await ScanAsync(messageList, sessionId ?? SessionId.New(),
            options.DefaultSenderId, options.DefaultReceiverId, ct, SystemPromptOf(messageList)).ConfigureAwait(false);
    }

    /// <summary>Returns the conversation's system prompt, if one was supplied.</summary>
    private static string? SystemPromptOf(IReadOnlyList<ChatMessage> msgs)
    {
        for (var i = 0; i < msgs.Count; i++)
        {
            if (msgs[i].Role == ChatRole.System) return msgs[i].Text;
        }

        return null;
    }

    private async ValueTask<SentinelError?> ScanAsync(
        IReadOnlyList<ChatMessage> msgs,
        SessionId sessionId,
        AgentId sender,
        AgentId receiver,
        CancellationToken ct,
        string? systemPrompt = null,
        IReadOnlySet<string>? placeholders = null)
    {
        var ctx = placeholders is null
            ? new SentinelContext(sender, receiver, sessionId, msgs, [], systemPrompt: systemPrompt)
            : new SentinelContext(sender, receiver, sessionId, msgs, [], systemPrompt: systemPrompt) { RedactionPlaceholders = placeholders };
        using var scanActivity = _activitySource.StartActivity("sentinel.scan");
        var pipelineResult = await pipeline.RunAsync(ctx, ct).ConfigureAwait(false);
        await AppendAuditAsync(pipelineResult, sessionId, ct).ConfigureAwait(false);

        scanActivity?.SetTag("sentinel.severity", pipelineResult.MaxSeverity.ToString());
        scanActivity?.SetTag("sentinel.is_clean", pipelineResult.IsClean);
        scanActivity?.SetTag("sentinel.threat_count", pipelineResult.Detections.Count);
        var topDetector = pipelineResult.Detections.MaxBy(d => d.Severity);
        if (topDetector is not null)
            scanActivity?.SetTag("sentinel.top_detector", topDetector.DetectorId.Value);

        if (pipelineResult.IsClean) return null;

        foreach (var d in pipelineResult.Detections)
        {
            var tags = new TagList
            {
                { "severity", d.Severity.ToString() },
                { "detector", d.DetectorId.Value }
            };
            SentinelMetrics.Threats.Add(1, tags);
        }

        var action = SentinelActionRanking.MostRestrictive(pipelineResult.Detections.Select(options.EffectiveAction));

        if ((action == SentinelAction.Quarantine || action == SentinelAction.Alert) && alertSink is not null)
        {
            var top = Representative(pipelineResult, action);
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
            var top = ex.PipelineResult.Detections.Count > 0
                ? Representative(ex.PipelineResult, action)
                : Representative(pipelineResult, action);
            return new SentinelError.ThreatDetected(top, action, sessionId);
        }

        return null;
    }

    /// <summary>The detection that drove <paramref name="action"/>: highest severity among those whose
    /// effective action equals it, so an alert never carries a detection whose own action was weaker.</summary>
    private DetectionResult Representative(PipelineResult result, SentinelAction action)
    {
        DetectionResult? best = null;
        foreach (var d in result.Detections)
        {
            if (options.EffectiveAction(d) != action) continue;
            if (best is null || d.Severity > best.Severity) best = d;
        }
        return best ?? DetectionResult.Clean(new DetectorId("unknown"));
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
        SessionId sessionId,
        CancellationToken ct)
    {
        foreach (var detection in result.Detections)
        {
            // Hash and PreviousHash are assigned by the store when it links the entry into its chain.
            var entry = new AuditEntry(
                Guid.NewGuid().ToString("N"),
                DateTimeOffset.UtcNow,
                Hash: string.Empty, PreviousHash: null,
                detection.Severity,
                detection.DetectorId.Value,
                detection.ActionOverride == SentinelAction.Redact
                    ? detection.Reason + "; not redacted"
                    : detection.Reason,
                SessionId: sessionId.Value);
            await auditStore.AppendAndForwardAsync(entry, _forwarders, ct).ConfigureAwait(false);
        }
    }
}
