using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.AI;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Redaction;
using AI.Sentinel.Transparency;
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
    private readonly Disclosure _disclosure;
    private int _rateLimiterWriteCount;

    /// <summary>Creates the pipeline.</summary>
    /// <param name="innerClient">The underlying <see cref="IChatClient"/> the pipeline forwards sanitized requests to.</param>
    /// <param name="pipeline">Detection pipeline that scans prompt and response messages.</param>
    /// <param name="auditStore">Synchronous audit store that receives every audit entry on the hot path.</param>
    /// <param name="interventionEngine">Intervention engine that applies the configured action when threats are detected.</param>
    /// <param name="options">Sentinel configuration (rate limits, thresholds, hardening prefix, etc.).</param>
    /// <param name="alertSink">Optional alert sink invoked fire-and-forget when an action escalates to <c>Quarantine</c> or <c>Alert</c>.</param>
    /// <param name="forwarders">Optional audit forwarders that mirror every audit entry to external systems fire-and-forget. Default empty.</param>
    /// <param name="pipelineName">The named pipeline's name, recorded in the transparency mark; <see langword="null"/> for the default pipeline.</param>
    /// <param name="timeProvider">Clock for the transparency mark and its idle-session eviction; defaults to <see cref="TimeProvider.System"/>.</param>
    internal SentinelPipeline(
        IChatClient innerClient,
        IDetectionPipeline pipeline,
        IAuditStore auditStore,
        InterventionEngine interventionEngine,
        SentinelOptions options,
        IAlertSink? alertSink = null,
        IEnumerable<IAuditForwarder>? forwarders = null,
        string? pipelineName = null,
        TimeProvider? timeProvider = null)
    {
        this.innerClient = innerClient;
        this.pipeline = pipeline;
        this.auditStore = auditStore;
        this.interventionEngine = interventionEngine;
        this.options = options;
        this.alertSink = alertSink;
        _forwarders = AuditForwarding.Snapshot(forwarders);
        _disclosure = new Disclosure(options, pipelineName, timeProvider ?? TimeProvider.System);

        // Tool calls the model makes run inside a FunctionInvokingChatClient below this pipeline, if there is
        // one; its hook restores their arguments and redacts their results for the current call.
        RedactionScope.InstallToolHook(innerClient);
    }

    // EmbeddingGenerator not set — all SemanticDetectorBase subclasses return Clean.
    // Set SentinelOptions.EmbeddingGenerator to enable language-agnostic detection.

    /// <summary>This pipeline's Art. 50 disclosure; exposed for tests.</summary>
    internal Disclosure Disclosure => _disclosure;

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
    /// are replaced by placeholders such as <c>[EMAIL_1_k3f9x2]</c> in everything sent to the model: every message,
    /// tool-call arguments and tool results, including the results of tools the model calls during this call, and
    /// <see cref="ChatOptions.Instructions"/>, which is redacted in a copy of <paramref name="chatOptions"/>. The tag
    /// is random per call, so a placeholder from another call never resolves to a value of this one.
    /// The other detectors judge the redacted request. The response is scanned as the model produced it and
    /// then, when <see cref="SentinelOptions.RestoreRedactedValues"/> is set, restored. The mapping lives only
    /// for this call. Any failure to redact fails the call closed: nothing is sent unredacted.
    /// When <see cref="SentinelOptions.Transparency"/> is enabled, a successful reply with assistant text is then
    /// marked as AI-generated, see <see cref="TransparencyKeys"/>, and may get the notice; the notice Sentinel added
    /// to an earlier reply is removed from the history before it is scanned and sent.
    /// </remarks>
    public async ValueTask<Result<ChatResponse, SentinelError>> GetResponseResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var callerSession = CallerSessionIdFor(chatOptions);
        var sessionId = callerSession ?? SessionId.New();
        var (request, requestError) = await PrepareRequestAsync(messages, chatOptions, sessionId, ct).ConfigureAwait(false);
        if (requestError is not null)
            return Result<ChatResponse, SentinelError>.Failure(requestError);

        var scope = EnterScope(in request);

        var inner = await CallInnerAsync(request, sessionId, "Inner client failed.",
            (sent, token) => innerClient.GetResponseAsync(sent, request.Options, token),
            ct).ConfigureAwait(false);
        if (inner.IsFailure)
            return Result<ChatResponse, SentinelError>.Failure(inner.Error);

        var response = inner.Value;

        IReadOnlyList<ChatMessage> responseMessages =
            response.Messages as IReadOnlyList<ChatMessage> ?? response.Messages.ToList();
        var responseError = await CheckResponseAsync(responseMessages, request, scope, sessionId, ct).ConfigureAwait(false);
        if (responseError is not null)
            return Result<ChatResponse, SentinelError>.Failure(responseError);

        var restored = RestoreResponse(scope, response, static (session, r) =>
        {
            r.Messages = session.Restore(r.Messages);
            return r;
        });
        if (restored.IsSuccess)
            await DiscloseAsync(restored.Value, sessionId, callerSession is not null, chatOptions?.ModelId).ConfigureAwait(false);
        return restored;
    }

    /// <summary>
    /// Marks the reply and adds the notice after the scan and the restore, so detectors never judge it and it is
    /// never taken for model output. The session's DISCLOSED entry is written with <see cref="CancellationToken.None"/>:
    /// the reply is being returned, so the evidence of its disclosure must be recorded. When the write fails the
    /// exception reaches the caller and the reply is not delivered, so the session's claim is rolled back.
    /// </summary>
    private async ValueTask DiscloseAsync(ChatResponse response, SessionId sessionId, bool callerSession, string? requestModelId)
    {
        if (!_disclosure.TryDisclose(response, sessionId, requestModelId, out var entry, remember: callerSession) || entry is null)
            return;

        try
        {
            await auditStore.AppendAndForwardAsync(entry, _forwarders, CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            _disclosure.Retract(entry);
            throw;
        }
    }

    /// <summary>A request after its redaction and prompt scan, ready to send.</summary>
    /// <param name="Messages">The request as the model will see it, redacted when <paramref name="Session"/> is set.</param>
    /// <param name="Options">The caller's options, or a copy with redacted <see cref="ChatOptions.Instructions"/>.</param>
    /// <param name="Session">This call's redaction session; null when no detector redacts.</param>
    /// <param name="Parent">The scope of an enclosing Sentinel call, when this one runs below another.</param>
    /// <param name="SystemPrompt">The conversation's system prompt, if any.</param>
    /// <param name="SentPlaceholders">Every placeholder-shaped token in <paramref name="Messages"/>.</param>
    /// <param name="Redactors">The redacting detectors, read once for the whole call.</param>
    private readonly record struct PreparedRequest(
        IReadOnlyList<ChatMessage> Messages,
        ChatOptions? Options,
        IReadOnlyList<IRedactingDetector> Redactors,
        RedactionSession? Session,
        RedactionScope? Parent,
        string? SystemPrompt,
        IReadOnlySet<string>? SentPlaceholders);

    /// <summary>Checks the rate limit, redacts the request and scans the redacted request.</summary>
    private async ValueTask<(PreparedRequest Request, SentinelError? Error)> PrepareRequestAsync(
        IEnumerable<ChatMessage> messages, ChatOptions? chatOptions, SessionId sessionId, CancellationToken ct)
    {
        var rateError = CheckRateLimit(chatOptions);
        if (rateError is not null)
            return (default, rateError);

        // Sentinel's own notice on earlier replies is neither scanned nor sent to the model.
        var messageList = _disclosure.StripNotice(messages as IReadOnlyList<ChatMessage> ?? messages.ToList());

        var parent = RedactionScope.Current;
        var redactors = pipeline.Redactors;
        var session = redactors.Count > 0 ? new RedactionSession(redactors) : null;
        var (redacted, redactionError) = Redact(session, messageList, chatOptions);
        if (redactionError is not null)
            return (default, redactionError);
        messageList = redacted.Messages;

        var (scanned, systemPrompt) = WithInstructions(messageList, redacted.Options?.Instructions);

        // The request holds this call's placeholders and those of any enclosing Sentinel call; none is a value.
        var promptError = await ScanAsync(scanned, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt,
            new Exemptions(RedactionScope.ExemptPlaceholders(session, parent)), chatOptions?.ModelId).ConfigureAwait(false);
        if (promptError is not null)
            return (default, promptError);

        // Every placeholder-shaped token in the request the model is about to see. For the detectors that redacted
        // it none is a raw value, and the model may legitimately repeat one, including a literal left in history
        // from an earlier round trip. Only those detectors get to exempt them, see SentinelContext.
        return (new PreparedRequest(messageList, redacted.Options, redactors, session, parent, systemPrompt, redacted.Placeholders), null);
    }

    /// <summary>
    /// Makes this call's redaction scope current, so the tool hook of a function-invoking client below sees it.
    /// Deliberately not async: the value is set in the calling async method's context, so it flows into the inner
    /// clients and never back out to that method's caller. An enclosing Sentinel's scope becomes the parent, so
    /// a tool below both resolves both layers.
    /// </summary>
    private RedactionScope? EnterScope(in PreparedRequest request)
    {
        if (request.Session is null)
            return null;

        var scope = new RedactionScope(request.Session, options.RestoreRedactedValues, request.Parent);
        RedactionScope.Current = scope;
        return scope;
    }

    /// <summary>
    /// Sends the hardened request through <paramref name="call"/> and records this call's redactions. They are
    /// recorded when the inner client fails too, with <see cref="CancellationToken.None"/>: the request was sent,
    /// so its redactions are compliance evidence even when the call was cancelled.
    /// </summary>
    private async ValueTask<Result<T, SentinelError>> CallInnerAsync<T>(
        PreparedRequest request, SessionId sessionId, string failureMessage,
        Func<IReadOnlyList<ChatMessage>, CancellationToken, Task<T>> call, CancellationToken ct)
    {
        T value;
        try
        {
            value = await call(ApplyHardening(request.Messages), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await AppendRedactionsAsync(request.Session, sessionId, CancellationToken.None).ConfigureAwait(false);
            return Result<T, SentinelError>.Failure(new SentinelError.PipelineFailure(failureMessage, ex));
        }

        await AppendRedactionsAsync(request.Session, sessionId, ct).ConfigureAwait(false);
        return Result<T, SentinelError>.Success(value);
    }

    /// <summary>Fails the call when a tool invocation could not be redacted, then scans the response as the model
    /// produced it, before any restore, so restored values never trigger a response detection.</summary>
    private async ValueTask<SentinelError?> CheckResponseAsync(
        IReadOnlyList<ChatMessage> responseMessages, PreparedRequest request, RedactionScope? scope,
        SessionId sessionId, CancellationToken ct)
    {
        if (scope is { Failed: true })
        {
            return new SentinelError.PipelineFailure(
                "AI.Sentinel could not redact a tool call made during the request; the request was stopped and nothing unredacted was sent.");
        }

        var exempt = new Exemptions(
            RedactionScope.ExemptPlaceholders(request.Session, request.Parent),
            request.SentPlaceholders,
            RedactorIds(request.Redactors));
        return await ScanAsync(responseMessages, sessionId,
            options.DefaultReceiverId, options.DefaultSenderId, ct, request.SystemPrompt, exempt, request.Options?.ModelId).ConfigureAwait(false);
    }

    /// <summary>Restores the redacted values in <paramref name="response"/> when this call redacted anything and
    /// <see cref="SentinelOptions.RestoreRedactedValues"/> is set; a failure to restore fails the call.</summary>
    private Result<T, SentinelError> RestoreResponse<T>(
        RedactionScope? scope, T response, Func<RedactionSession, T, T> restore)
    {
        if (scope is not { Session.HasRedactions: true } || !options.RestoreRedactedValues)
            return Result<T, SentinelError>.Success(response);

        try
        {
            return Result<T, SentinelError>.Success(restore(scope.Session, response));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Result<T, SentinelError>.Failure(RedactionFailed(ex));
        }
    }

    /// <summary>The request after redaction: messages, options and the placeholder-shaped tokens they hold.</summary>
    private readonly record struct RedactedInput(
        IReadOnlyList<ChatMessage> Messages, ChatOptions? Options, IReadOnlySet<string>? Placeholders);

    /// <summary>
    /// Redacts the messages and <see cref="ChatOptions.Instructions"/>, which providers send as a system prompt. The
    /// instructions are redacted into a copy of the options, so the caller's options are never mutated; options
    /// with nothing to redact are passed on as they are. Nothing in the options is restored: they never come back.
    /// </summary>
    private static (RedactedInput Input, SentinelError? Error) Redact(
        RedactionSession? session, IReadOnlyList<ChatMessage> messages, ChatOptions? options)
    {
        if (session is null)
            return (new RedactedInput(messages, options, null), null);

        try
        {
            var redacted = session.RedactRequest(messages, options?.Instructions);
            var sentOptions = options;
            if (options is not null && !string.Equals(redacted.Instructions, options.Instructions, StringComparison.Ordinal))
            {
                sentOptions = options.Clone();
                sentOptions.Instructions = redacted.Instructions;
            }
            return (new RedactedInput(redacted.Messages, sentOptions, redacted.Placeholders), null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (default, RedactionFailed(ex));
        }
    }

    private static readonly IReadOnlySet<string> NoStrings = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>Placeholders a scan must not flag; see <see cref="SentinelContext.PlaceholdersExemptFor"/>.</summary>
    private readonly record struct Exemptions(
        IReadOnlySet<string>? Minted,
        IReadOnlySet<string>? Request = null,
        IReadOnlySet<string>? RedactorIds = null);

    private static HashSet<string> RedactorIds(IReadOnlyList<IRedactingDetector> redactors)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in redactors)
        {
            ids.Add(r.Id.Value);
        }
        return ids;
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

    /// <summary>Redacts and scans the prompt, buffers the full inner streaming response, scans it and restores
    /// the redacted values in the buffered updates. Returns the buffer on success or a <see cref="SentinelError"/>
    /// on failure.</summary>
    /// <remarks>
    /// Buffering is intentional — it ensures a quarantined response never reaches the caller.
    /// Time-to-first-token equals total LLM response latency on this path.
    /// Redaction works as for <see cref="GetResponseResultAsync"/>. The response is scanned as the model streamed
    /// it, then restored update by update: a placeholder split across updates is restored whole, and no update
    /// carries part of one. The number of updates, their metadata and their non-text content are kept.
    /// </remarks>
    public async ValueTask<Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>> GetStreamingResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var sessionId = SessionIdFor(chatOptions);
        var (request, requestError) = await PrepareRequestAsync(messages, chatOptions, sessionId, ct).ConfigureAwait(false);
        if (requestError is not null)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(requestError);

        var scope = EnterScope(in request);

        var inner = await CallInnerAsync(request, sessionId, "Inner client streaming failed.",
            async (sent, token) =>
            {
                var updates = new List<ChatResponseUpdate>();
                await foreach (var update in innerClient.GetStreamingResponseAsync(sent, request.Options, token).ConfigureAwait(false))
                    updates.Add(update);
                return updates;
            },
            ct).ConfigureAwait(false);
        if (inner.IsFailure)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(inner.Error);

        var buffer = inner.Value;

        // The messages the updates make up, the same shape the non-streaming path scans.
        var responseMessages = buffer.ToChatResponse().Messages;
        var responseError = await CheckResponseAsync(
            responseMessages as IReadOnlyList<ChatMessage> ?? responseMessages.ToList(),
            request, scope, sessionId, ct).ConfigureAwait(false);
        if (responseError is not null)
            return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Failure(responseError);

        return RestoreResponse<IReadOnlyList<ChatResponseUpdate>>(scope, buffer,
            static (session, updates) => session.RestoreUpdates(updates));
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
        var (scanned, systemPrompt) = WithInstructions(messageList, chatOptions?.Instructions);
        return await ScanAsync(scanned, sessionId ?? SessionIdFor(chatOptions),
            options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt, llmId: chatOptions?.ModelId).ConfigureAwait(false);
    }

    /// <summary>
    /// The messages the detectors judge, and the system prompt they compare against. Providers send
    /// <see cref="ChatOptions.Instructions"/> to the model as a system prompt, so the scan sees them as a leading
    /// system message and the system prompt includes them. The messages sent to the model are not changed.
    /// </summary>
    private static (IReadOnlyList<ChatMessage> Scanned, string? SystemPrompt) WithInstructions(
        IReadOnlyList<ChatMessage> messages, string? instructions)
    {
        var systemMessage = SystemPromptOf(messages);
        if (string.IsNullOrEmpty(instructions))
            return (messages, systemMessage);

        var scanned = new List<ChatMessage>(messages.Count + 1) { new(ChatRole.System, instructions) };
        scanned.AddRange(messages);
        var systemPrompt = string.IsNullOrEmpty(systemMessage) ? instructions : $"{instructions}\n\n{systemMessage}";
        return (scanned, systemPrompt);
    }

    /// <summary>The <see cref="ChatOptions.AdditionalProperties"/> key that names the caller's session.</summary>
    public const string SessionIdKey = "sentinel.session_id";

    /// <summary>
    /// The session this call's audit entries belong to: the string under <see cref="SessionIdKey"/> in
    /// <see cref="ChatOptions.AdditionalProperties"/>, else <see cref="ChatOptions.ConversationId"/>, else a new id.
    /// One conversation's calls then share a session in the audit log, the dashboard and alert de-duplication.
    /// </summary>
    private static SessionId SessionIdFor(ChatOptions? chatOptions) => CallerSessionIdFor(chatOptions) ?? SessionId.New();

    /// <summary>The session the caller named, or <see langword="null"/> when this call is its own session.</summary>
    private static SessionId? CallerSessionIdFor(ChatOptions? chatOptions)
    {
        if (chatOptions?.AdditionalProperties?.GetValueOrDefault(SessionIdKey) is string key && !string.IsNullOrWhiteSpace(key))
            return new SessionId(key);
        if (!string.IsNullOrWhiteSpace(chatOptions?.ConversationId))
            return new SessionId(chatOptions.ConversationId);
        return null;
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
        Exemptions exemptions = default,
        string? llmId = null)
    {
        var ctx = exemptions.Minted is null
            ? new SentinelContext(sender, receiver, sessionId, msgs, []) { SystemPrompt = systemPrompt, LlmId = llmId }
            : new SentinelContext(sender, receiver, sessionId, msgs, [])
            {
                SystemPrompt = systemPrompt,
                LlmId = llmId,
                RedactionPlaceholders = exemptions.Minted,
                RequestPlaceholders = exemptions.Request ?? NoStrings,
                RedactingDetectorIds = exemptions.RedactorIds ?? NoStrings,
            };
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
            ?.GetValueOrDefault(SessionIdKey) as string ?? "__global__";
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
                    : detection.Reason)
            {
                SessionId = sessionId.Value,
            };
            await auditStore.AppendAndForwardAsync(entry, _forwarders, ct).ConfigureAwait(false);
        }
    }
}
