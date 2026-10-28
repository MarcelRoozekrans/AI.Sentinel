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
public sealed partial class SentinelPipeline
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

    /// <summary>The client this pipeline forwards to; a <see cref="SentinelChatClient"/> delegates to the same one.</summary>
    internal IChatClient InnerClient => innerClient;

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

        // The inner client owns its response, and a caching client below Sentinel may hand out the same
        // instance again, so the restore goes into a copy and the inner response keeps its placeholders.
        var restored = RestoreResponse(scope, response, static (session, r) => new ChatResponse(session.Restore(r.Messages))
        {
            ResponseId = r.ResponseId,
            ConversationId = r.ConversationId,
            ModelId = r.ModelId,
            CreatedAt = r.CreatedAt,
            FinishReason = r.FinishReason,
            Usage = r.Usage,
            ContinuationToken = r.ContinuationToken,
            RawRepresentation = r.RawRepresentation,
            AdditionalProperties = r.AdditionalProperties is null ? null : new AdditionalPropertiesDictionary(r.AdditionalProperties),
        });
        if (restored.IsFailure)
            return restored;
        return Result<ChatResponse, SentinelError>.Success(
            await DiscloseAsync(restored.Value, sessionId, callerSession is not null, chatOptions?.ModelId).ConfigureAwait(false));
    }

    /// <summary>
    /// Marks the reply and adds the notice after the scan and the restore, so detectors never judge it and it is
    /// never taken for model output. Returns the response to deliver: disclosure works on a copy and never changes
    /// the response it is given.
    /// </summary>
    private async ValueTask<ChatResponse> DiscloseAsync(ChatResponse response, SessionId sessionId, bool callerSession, string? requestModelId)
    {
        if (_disclosure.TryDisclose(response, sessionId, requestModelId, out var disclosed, out var entry, remember: callerSession) && entry is not null)
            await AppendDisclosedAsync(entry).ConfigureAwait(false);
        return disclosed;
    }

    /// <summary>The streaming counterpart of <see cref="DiscloseAsync(ChatResponse, SessionId, bool, string?)"/>;
    /// returns the updates to deliver.</summary>
    private async ValueTask<IReadOnlyList<ChatResponseUpdate>> DiscloseAsync(
        IReadOnlyList<ChatResponseUpdate> updates, SessionId sessionId, bool callerSession, string? requestModelId)
    {
        if (!_disclosure.TryDisclose(updates, sessionId, requestModelId, out var disclosed, out var entry, remember: callerSession))
            return updates;
        if (entry is not null)
            await AppendDisclosedAsync(entry).ConfigureAwait(false);
        return disclosed;
    }

    /// <summary>
    /// Writes the session's DISCLOSED entry with <see cref="CancellationToken.None"/>: the reply is being returned,
    /// so the evidence of its disclosure must be recorded. When the write fails the exception reaches the caller and
    /// the reply is not delivered, so the session's claim is rolled back.
    /// </summary>
    private async ValueTask AppendDisclosedAsync(AuditEntry entry)
    {
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
        var rateError = CheckRateLimit(RateLimitSessionIdFor(chatOptions));
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
        // What follows the last assistant message is new, a trailing assistant prefill aside: the earlier messages
        // were judged on an earlier turn.
        var promptError = await ScanAsync(scanned, sessionId,
            options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt,
            new Exemptions(RedactionScope.ExemptPlaceholders(session, parent)), chatOptions?.ModelId,
            newMessagesFrom: NewFromAfterLastAssistant(scanned)).ConfigureAwait(false);
        if (promptError is not null)
        {
            // A quarantined prompt was redacted before it was scanned, so what was masked is evidence too. A rate
            // limit or redaction failure returns earlier: nothing was masked, or the session is unusable.
            if (promptError is SentinelError.ThreatDetected)
                await AppendRedactionsAsync(session, sessionId, ct).ConfigureAwait(false);
            return (default, promptError);
        }

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
    /// so its redactions are compliance evidence even when the call was cancelled. A cancelled call rethrows its
    /// <see cref="OperationCanceledException"/> after that. Redactions of a quarantined prompt are recorded by
    /// <see cref="PrepareRequestAsync"/>, which never reaches this method.
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
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            await AppendRedactionsAsync(request.Session, sessionId, CancellationToken.None).ConfigureAwait(false);
            throw;
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

        await AppendRedactionsAsync(session.CountsByDetector, sessionId, ct).ConfigureAwait(false);
    }

    /// <summary>One audit entry per redacting detector in <paramref name="byDetector"/>, counts only, and one Redact
    /// notification; nothing when it is empty.</summary>
    private async Task AppendRedactionsAsync(
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> byDetector, SessionId sessionId, CancellationToken ct)
    {
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
    /// Transparency works as for <see cref="GetResponseResultAsync"/>: the mark goes on the update whose properties
    /// <c>ToChatResponse</c> merges into the response, see <see cref="TransparencyKeys"/>, and the notice is a leading
    /// text in the first update with text of the last assistant message with text. Nothing else about the updates
    /// changes.
    /// </remarks>
    public async ValueTask<Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>> GetStreamingResultAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        CancellationToken ct)
    {
        var callerSession = CallerSessionIdFor(chatOptions);
        var sessionId = callerSession ?? SessionId.New();
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

        var restored = RestoreResponse<IReadOnlyList<ChatResponseUpdate>>(scope, buffer,
            static (session, updates) => session.RestoreUpdates(updates));
        if (restored.IsFailure)
            return restored;
        return Result<IReadOnlyList<ChatResponseUpdate>, SentinelError>.Success(
            await DiscloseAsync(restored.Value, sessionId, callerSession is not null, chatOptions?.ModelId).ConfigureAwait(false));
    }

    /// <summary>Runs detection against <paramref name="messages"/> without invoking the inner chat client.
    /// Useful for hook adapters that scan caller-supplied prompts or tool payloads where there is no LLM response.</summary>
    /// <remarks>
    /// Rate-limit check fires first; on exceeded quota the method returns <see cref="SentinelError.RateLimitExceeded"/>.
    /// Otherwise runs a single detection pass and returns <see langword="null"/> on clean,
    /// <see cref="SentinelError.ThreatDetected"/> on detection.
    /// When <paramref name="sessionId"/> is supplied the audit entries carry it; otherwise a fresh id is minted per call.
    /// Every message is judged as new, and so is <see cref="ChatOptions.Instructions"/>, which the scan sees as a
    /// leading system message.
    /// </remarks>
    /// <param name="messages">The messages to scan.</param>
    /// <param name="chatOptions">Options used for the rate-limit check and whose
    /// <see cref="ChatOptions.Instructions"/> are scanned; <see langword="null"/> for none.</param>
    /// <param name="sessionId">The session recorded on the audit entries, as the <see cref="SessionId"/> domain type;
    /// <see langword="null"/> mints a fresh id for this call.</param>
    /// <param name="ct">Cancellation token.</param>
    public ValueTask<SentinelError?> ScanMessagesAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions = null,
        SessionId? sessionId = null,
        CancellationToken ct = default)
        => ScanMessagesCoreAsync(messages, chatOptions, sessionId, findings: null, exemptPlaceholders: null, newMessagesFrom: 0, ct);

    /// <summary>As <see cref="ScanMessagesAsync"/>, but returns every detection of the scan with its effective
    /// action, so a host with no response to gate, such as a hook, can decide per detection.</summary>
    /// <remarks>Audit, alerts and interventions run as for <see cref="ScanMessagesAsync"/>. A clean scan, or one
    /// refused by the rate limit, returns an empty list. <see cref="ScanMessagesAsync"/> reports only the most
    /// restrictive action's representative, which loses a weaker-ranked detection a hook still has to surface,
    /// such as an Alert that co-fires with a Quarantine detection the hook maps to Allow.</remarks>
    /// <param name="messages">The messages to scan.</param>
    /// <param name="sessionId">The session the scan belongs to; <see langword="null"/> mints a fresh id.</param>
    /// <param name="newMessagesFrom">The index from which <paramref name="messages"/> are new in this scan, see
    /// <see cref="SentinelContext.NewMessagesFrom"/>; 0 marks every message new.</param>
    /// <param name="ct">Cancellation token.</param>
    internal async ValueTask<IReadOnlyList<ScanFinding>> ScanMessagesForFindingsAsync(
        IEnumerable<ChatMessage> messages,
        SessionId? sessionId,
        int newMessagesFrom,
        CancellationToken ct)
    {
        var findings = new List<ScanFinding>();
        await ScanMessagesCoreAsync(messages, chatOptions: null, sessionId, findings, exemptPlaceholders: null, newMessagesFrom, ct).ConfigureAwait(false);
        return findings;
    }

    /// <summary>As <see cref="ScanMessagesAsync"/>, but no detector flags the placeholders in
    /// <paramref name="exemptPlaceholders"/>: tokens a host such as the MCP proxy minted on earlier calls, which are
    /// no values. Null exempts nothing. <paramref name="newMessagesFrom"/> is the index from which
    /// <paramref name="messages"/> are new in this scan, see <see cref="SentinelContext.NewMessagesFrom"/>.</summary>
    internal ValueTask<SentinelError?> ScanMessagesExemptingAsync(
        IEnumerable<ChatMessage> messages,
        SessionId? sessionId,
        IReadOnlySet<string>? exemptPlaceholders,
        int newMessagesFrom,
        CancellationToken ct)
        => ScanMessagesCoreAsync(messages, chatOptions: null, sessionId, findings: null, exemptPlaceholders, newMessagesFrom, ct);

    /// <summary>
    /// Redacts content a host hands Sentinel on its way to the model, such as a tool result in the MCP proxy or a
    /// hook, and scans the redacted copy. Never calls the inner client.
    /// </summary>
    /// <remarks>
    /// The content is redacted with a new <see cref="RedactionSession"/>: text as a whole, JSON in its string values
    /// only. <see cref="HostRedactionRequest.Context"/> is then redacted in the scan copy only, so a value it shares
    /// with the content is counted once, for the content. The scan judges the redacted context, the redacted
    /// content and <see cref="HostRedactionRequest.Unredactable"/> as it is, with this call's placeholders and
    /// <see cref="HostRedactionRequest.KnownPlaceholders"/> exempt. The content's counts are returned, not audited:
    /// a host that delivers the redacted content records them with
    /// <see cref="AppendRedactionsAsync(HostRedactionResult, string, CancellationToken)"/>. With no redacting detector the request is scanned as it is. When the redaction
    /// fails, the session is discarded and the request is scanned unredacted, as in 3.0: the result has
    /// <see cref="HostRedactionResult.FellBack"/> set, the input content, and findings with their severity action,
    /// audited with <c>; not redacted</c>. The exception is not kept, because its message can carry the value.
    /// </remarks>
    internal async ValueTask<HostRedactionResult> RedactAndScanAsync(
        HostRedactionRequest request, SessionId? sessionId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        foreach (var item in request.Content)
        {
            if (item.Text is null && item.Json is null)
                throw new ArgumentException("Every content item must be made with HostContent.FromText or HostContent.FromJson.", nameof(request));
        }

        var sid = sessionId ?? SessionId.New();
        var redactors = pipeline.Redactors;
        if (redactors.Count == 0)
            return await ScanHostVerbatimAsync(request, sid, fellBack: false, checkRateLimit: true, ct).ConfigureAwait(false);

        // As on the chat path, the rate limit is checked before anything is redacted.
        var rateError = CheckRateLimit(rateSession: null);
        if (rateError is not null)
            return new HostRedactionResult(request.Content, [], rateError, EmptyCounts, [], FellBack: false) { SessionId = sid.Value };

        var redacted = TryRedactHost(request, redactors);
        if (redacted is not { } host)
            return await ScanHostVerbatimAsync(request, sid, fellBack: true, checkRateLimit: false, ct).ConfigureAwait(false);

        var exempt = new HashSet<string>(StringComparer.Ordinal);
        exempt.UnionWith(RedactionScope.ExemptPlaceholders(host.Session, parent: null)!);
        if (request.KnownPlaceholders is not null)
            exempt.UnionWith(request.KnownPlaceholders);

        var findings = new List<ScanFinding>();
        // The context is what the content answers; only the content and the unredactable content are new.
        var error = await ScanCollectingAsync(
            HostScanMessages(host.Context, host.Content, request), sid, findings, exempt, host.Context.Count, ct).ConfigureAwait(false);

        return new HostRedactionResult(host.Content, findings, error, SumByType(host.CountsByDetector), host.Minted, FellBack: false)
        {
            RedactedByDetector = host.CountsByDetector,
            SessionId = sid.Value,
        };
    }

    /// <summary>
    /// Records the redactions of <paramref name="result"/>: one <c>REDACTED</c> entry per redacting detector, counts
    /// only, and one Redact notification; nothing when it redacted nothing. A host calls this only when it delivers
    /// the redacted content. <see cref="RedactAndScanAsync"/> cannot know that: a finding that a hook maps to Warn is
    /// delivered, while one the MCP proxy blocks is withheld.
    /// </summary>
    /// <param name="result">The result whose content the host delivered.</param>
    /// <param name="sessionId">The session to record the entries for, usually <see cref="HostRedactionResult.SessionId"/>.</param>
    /// <param name="ct">Cancellation token.</param>
    internal Task AppendRedactionsAsync(HostRedactionResult result, string sessionId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        return AppendRedactionsAsync(result.RedactedByDetector, new SessionId(sessionId), ct);
    }

    private static readonly IReadOnlyDictionary<string, int> EmptyCounts = new Dictionary<string, int>(StringComparer.Ordinal);

    /// <summary>The host request after redaction; the counts and placeholders are those of the content only.</summary>
    private readonly record struct RedactedHost(
        RedactionSession Session,
        IReadOnlyList<HostContent> Content,
        IReadOnlyList<ChatMessage> Context,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> CountsByDetector,
        IReadOnlyList<MintedPlaceholder> Minted);

    /// <summary>Redacts the content, takes its counts and placeholders, then redacts the context into a scan copy.
    /// Null when anything fails; the exception is deliberately dropped, because its message can carry the value.</summary>
    private static RedactedHost? TryRedactHost(HostRedactionRequest request, IReadOnlyList<IRedactingDetector> redactors)
    {
        try
        {
            var session = new RedactionSession(redactors) { KnownPlaceholders = request.KnownPlaceholders };
            var content = new List<HostContent>(request.Content.Count);
            foreach (var item in request.Content)
            {
                content.Add(item.Text is { } text
                    ? HostContent.FromText(session.Redact(text))
                    : HostContent.FromJson(session.RedactJsonValues(item.Json!.Value)));
            }

            // The counts and tokens are the content's alone. Restorability is read after the context is redacted:
            // the context can show that a value the content holds is a secret, which makes its token non-restorable.
            var counts = session.CountsByDetector;
            var contentTokens = session.MintedTokens;
            var context = request.Context.Count == 0 ? request.Context : session.RedactRequest(request.Context).Messages;
            var minted = new List<MintedPlaceholder>(contentTokens.Count);
            foreach (var m in session.ExportMinted())
            {
                if (contentTokens.Contains(m.Token))
                    minted.Add(m);
            }
            return new RedactedHost(session, content, context, counts, minted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>The 3.0 scan of a host request: context, content and unredactable content as they are.</summary>
    private async ValueTask<HostRedactionResult> ScanHostVerbatimAsync(
        HostRedactionRequest request, SessionId sessionId, bool fellBack, bool checkRateLimit, CancellationToken ct)
    {
        if (checkRateLimit && CheckRateLimit(rateSession: null) is { } rateError)
            return new HostRedactionResult(request.Content, [], rateError, EmptyCounts, [], fellBack) { SessionId = sessionId.Value };

        var findings = new List<ScanFinding>();
        var error = await ScanCollectingAsync(
            HostScanMessages(request.Context, request.Content, request), sessionId, findings, request.KnownPlaceholders,
            request.Context.Count, ct).ConfigureAwait(false);
        return new HostRedactionResult(request.Content, findings, error, EmptyCounts, [], fellBack) { SessionId = sessionId.Value };
    }

    /// <summary>The context, then one message per content item under the content role, then the unredactable
    /// content.</summary>
    private static List<ChatMessage> HostScanMessages(
        IReadOnlyList<ChatMessage> context, IReadOnlyList<HostContent> content, HostRedactionRequest request)
    {
        var messages = new List<ChatMessage>(context.Count + content.Count + request.Unredactable.Count);
        messages.AddRange(context);
        foreach (var item in content)
        {
            messages.Add(new ChatMessage(request.ContentRole, item.ScanText()));
        }
        messages.AddRange(request.Unredactable);
        return messages;
    }

    private static Dictionary<string, int> SumByType(IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> byDetector)
    {
        var byType = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var counts in byDetector.Values)
        {
            foreach (var (type, count) in counts)
            {
                byType[type] = byType.GetValueOrDefault(type) + count;
            }
        }
        return byType;
    }

    private async ValueTask<SentinelError?> ScanMessagesCoreAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? chatOptions,
        SessionId? sessionId,
        List<ScanFinding>? findings,
        IReadOnlySet<string>? exemptPlaceholders,
        int newMessagesFrom,
        CancellationToken ct)
    {
        var rateError = CheckRateLimit(RateLimitSessionIdFor(chatOptions));
        if (rateError is not null) return rateError;

        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var (scanned, systemPrompt) = WithInstructions(messageList, chatOptions?.Instructions);
        // A leading instructions message shifts the caller's messages, and so a non-zero index, by one.
        return await ScanAsync(scanned, sessionId ?? SessionIdFor(chatOptions),
            options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt, new Exemptions(exemptPlaceholders),
            llmId: chatOptions?.ModelId, findings: findings,
            newMessagesFrom: ShiftForInstructions(newMessagesFrom, scanned.Count - messageList.Count)).ConfigureAwait(false);
    }

    /// <summary>The caller's index moved past <paramref name="shift"/> prepended instructions messages. An index of
    /// 0 marks every message new, the instructions included, so it stays 0.</summary>
    internal static int ShiftForInstructions(int newMessagesFrom, int shift) =>
        newMessagesFrom == 0 ? 0 : newMessagesFrom + shift;

    /// <summary>One scan with no rate-limit check, collecting every finding.</summary>
    private ValueTask<SentinelError?> ScanCollectingAsync(
        IReadOnlyList<ChatMessage> messages, SessionId sessionId, List<ScanFinding> findings,
        IReadOnlySet<string>? exemptPlaceholders, int newMessagesFrom, CancellationToken ct)
    {
        var systemPrompt = SystemPromptOf(messages);
        return ScanAsync(messages, sessionId, options.DefaultSenderId, options.DefaultReceiverId, ct, systemPrompt,
            new Exemptions(exemptPlaceholders), findings: findings, newMessagesFrom: newMessagesFrom);
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

    /// <summary>
    /// The <see cref="ChatOptions.AdditionalProperties"/> key that names the caller's session. The value is a
    /// non-blank string or a <see cref="SessionId"/>. It is the only caller input the rate limiter keys on; the audit
    /// also falls back to <see cref="ChatOptions.ConversationId"/>.
    /// </summary>
    public const string SessionIdKey = "sentinel.session_id";

    /// <summary>
    /// The session this call's audit entries belong to: the string or <see cref="SessionId"/> under
    /// <see cref="SessionIdKey"/> in <see cref="ChatOptions.AdditionalProperties"/>, else <see cref="ChatOptions.ConversationId"/>, else a new id.
    /// One conversation's calls then share a session in the audit log, the dashboard and alert de-duplication.
    /// </summary>
    private static SessionId SessionIdFor(ChatOptions? chatOptions) => CallerSessionIdFor(chatOptions) ?? SessionId.New();

    /// <summary>The session the caller named, or <see langword="null"/> when this call is its own session.</summary>
    private static SessionId? CallerSessionIdFor(ChatOptions? chatOptions)
    {
        if (NamedSessionIdFrom(chatOptions) is { } named)
            return named;
        if (!string.IsNullOrWhiteSpace(chatOptions?.ConversationId))
            return new SessionId(chatOptions.ConversationId);
        return null;
    }

    /// <summary>
    /// The rate-limit key the caller named under <see cref="SessionIdKey"/>, else <see langword="null"/> for the shared
    /// <c>__global__</c> key. <see cref="ChatOptions.ConversationId"/> is not a key: with the OpenAI Responses API it is
    /// the previous response id, so every turn would get a fresh bucket.
    /// </summary>
    private static SessionId? RateLimitSessionIdFor(ChatOptions? chatOptions) => NamedSessionIdFrom(chatOptions);

    /// <summary>The string or <see cref="SessionId"/> under <see cref="SessionIdKey"/>, when it is not blank.</summary>
    private static SessionId? NamedSessionIdFrom(ChatOptions? chatOptions)
    {
        var named = chatOptions?.AdditionalProperties?.GetValueOrDefault(SessionIdKey);
        if (named is SessionId typed && !string.IsNullOrWhiteSpace(typed.Value))
            return typed;
        if (named is string key && !string.IsNullOrWhiteSpace(key))
            return new SessionId(key);
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

    /// <summary>
    /// The index after the last <see cref="ChatRole.Assistant"/> message that precedes the caller's latest
    /// non-assistant message, or 0 when there is none. On a prompt scan the messages from there on are new: the
    /// caller's earlier messages were judged on the turn they arrived. A trailing run of assistant messages is an
    /// assistant prefill, such as an opening <c>{</c>, and is skipped first, so the user turn it follows is still
    /// new: <c>[user, prefill]</c> gives 0 and <c>[user, assistant, user, prefill]</c> gives 2.
    /// </summary>
    internal static int NewFromAfterLastAssistant(IReadOnlyList<ChatMessage> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        var i = messages.Count - 1;
        while (i >= 0 && messages[i].Role == ChatRole.Assistant) i--;
        for (; i >= 0; i--)
        {
            if (messages[i].Role == ChatRole.Assistant) return i + 1;
        }

        return 0;
    }

    private async ValueTask<SentinelError?> ScanAsync(
        IReadOnlyList<ChatMessage> msgs,
        SessionId sessionId,
        AgentId sender,
        AgentId receiver,
        CancellationToken ct,
        string? systemPrompt = null,
        Exemptions exemptions = default,
        string? llmId = null,
        List<ScanFinding>? findings = null,
        int newMessagesFrom = 0)
    {
        var ctx = BuildContext(msgs, sessionId, sender, receiver, systemPrompt, in exemptions, llmId, newMessagesFrom);
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

        if (findings is not null)
        {
            foreach (var d in pipelineResult.Detections)
                findings.Add(new ScanFinding(d, options.EffectiveAction(d)));
        }

        var action = SentinelActionRanking.MostRestrictive(pipelineResult.Detections.Select(options.EffectiveAction));

        if ((action == SentinelAction.Quarantine || action == SentinelAction.Alert) && alertSink is not null)
        {
            var top = Representative(pipelineResult, action);
            // Fire-and-forget: alert failures must never propagate to the caller.
            // Implementations of IAlertSink are expected to swallow their own exceptions.
            _ = alertSink.SendAsync(new SentinelError.ThreatDetected(top, action, sessionId) { Detections = pipelineResult.Detections }, CancellationToken.None).AsTask();
        }

        try
        {
            interventionEngine.Apply(pipelineResult, sessionId, sender, receiver);
        }
        catch (SentinelException ex)
        {
            // Quarantine: convert throw to Result instead of re-throwing.
            // Use the PipelineResult carried by the exception — it has the real detections.
            var caught = ex.PipelineResult.Detections.Count > 0 ? ex.PipelineResult : pipelineResult;
            return new SentinelError.ThreatDetected(Representative(caught, action), action, sessionId)
            {
                Detections = caught.Detections,
            };
        }

        return null;
    }

    private static SentinelContext BuildContext(
        IReadOnlyList<ChatMessage> msgs, SessionId sessionId, AgentId sender, AgentId receiver,
        string? systemPrompt, in Exemptions exemptions, string? llmId, int newMessagesFrom)
        => exemptions.Minted is null
            ? new SentinelContext(sender, receiver, sessionId, msgs, [])
            {
                SystemPrompt = systemPrompt,
                LlmId = llmId,
                NewMessagesFrom = newMessagesFrom,
            }
            : new SentinelContext(sender, receiver, sessionId, msgs, [])
            {
                SystemPrompt = systemPrompt,
                LlmId = llmId,
                NewMessagesFrom = newMessagesFrom,
                RedactionPlaceholders = exemptions.Minted,
                RequestPlaceholders = exemptions.Request ?? NoStrings,
                RedactingDetectorIds = exemptions.RedactorIds ?? NoStrings,
            };

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

    private SentinelError? CheckRateLimit(SessionId? rateSession)
    {
        if (options.MaxCallsPerSecond is not int maxRps) return null;

        var sessionKey = rateSession?.Value ?? "__global__";
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
