using System.Collections.Concurrent;
using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Transparency;

/// <summary>
/// Art. 50 disclosure for one pipeline: marks replies as AI-generated, adds the optional notice and decides when a
/// session's <see cref="AuditEntryKinds.DisclosedPolicyCode"/> entry is due. Reads <see cref="SentinelOptions"/>
/// live, as the rest of the pipeline does. The sessions that have seen the notice are kept per instance, so per
/// pipeline, and forgotten after <see cref="SentinelOptions.SessionIdleTimeout"/>.
/// </summary>
internal sealed class Disclosure
{
    internal const string MarkAndNoticeSummary = "Disclosed: machine-readable mark and notice";
    internal const string MarkSummary = "Disclosed: machine-readable mark";

    private static readonly object BoxedTrue = true;

    private readonly SentinelOptions _options;
    private readonly string? _pipelineName;
    private readonly TimeProvider _time;

    // Session id -> last disclosed reply, in Unix milliseconds of _time.
    private readonly ConcurrentDictionary<string, long> _sessions = new(StringComparer.Ordinal);
    private int _writeCount;

    /// <param name="options">The pipeline's options; <see cref="SentinelOptions.Transparency"/> is read on every call.</param>
    /// <param name="pipelineName">The named pipeline's name, or <see langword="null"/> for the default pipeline.</param>
    /// <param name="time">Clock for the mark's timestamp and for idle eviction.</param>
    internal Disclosure(SentinelOptions options, string? pipelineName, TimeProvider time)
    {
        _options = options;
        _pipelineName = pipelineName;
        _time = time;
    }

    /// <summary>Whether transparency is turned on.</summary>
    public bool Enabled => _options.Transparency.Enabled;

    /// <summary>The leading text the notice adds to a reply, or <see langword="null"/> when there is no notice text.</summary>
    public string? NoticeText =>
        string.IsNullOrWhiteSpace(_options.Transparency.Notice) ? null : _options.Transparency.Notice + "\n\n";

    /// <summary>Number of sessions currently remembered; for tests.</summary>
    internal int TrackedSessions => _sessions.Count;

    /// <summary>
    /// Removes Sentinel's own notice from the history: an assistant message whose leading content is exactly the
    /// notice text. Other roles and notice text in any other position are left alone. The caller's messages are
    /// not mutated; a changed message is a copy.
    /// </summary>
    public IReadOnlyList<ChatMessage> StripNotice(IReadOnlyList<ChatMessage> messages)
    {
        if (!Enabled || NoticeText is not { } notice)
            return messages;

        List<ChatMessage>? stripped = null;
        for (var i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            if (message.Role != ChatRole.Assistant
                || message.Contents.Count == 0
                || message.Contents[0] is not TextContent { Text: var text }
                || !string.Equals(text, notice, StringComparison.Ordinal))
            {
                continue;
            }

            stripped ??= new List<ChatMessage>(messages);
            stripped[i] = WithoutLeadingContent(message);
        }
        return stripped ?? messages;
    }

    private static ChatMessage WithoutLeadingContent(ChatMessage message)
    {
        var contents = new List<AIContent>(message.Contents.Count - 1);
        for (var i = 1; i < message.Contents.Count; i++)
            contents.Add(message.Contents[i]);
        var copy = message.Clone();
        copy.Contents = contents;
        return copy;
    }

    /// <summary>
    /// Discloses <paramref name="response"/> when it carries assistant text the person sees: marks it, adds the
    /// notice to the last assistant message with text when it is due, and returns the session's
    /// <see cref="AuditEntryKinds.DisclosedPolicyCode"/> entry the first time the session is disclosed.
    /// </summary>
    /// <param name="response">The reply, after the response scan and redaction restore.</param>
    /// <param name="session">The call's session.</param>
    /// <param name="requestModelId">The requested model, used when the response does not name one.</param>
    /// <param name="entry">The entry to append, or <see langword="null"/> when the session was already disclosed.</param>
    /// <param name="remember">False for a one-off session minted for this call: it is disclosed as new and not
    /// remembered, since no later call can share it.</param>
    /// <returns>True when the response was marked.</returns>
    public bool TryDisclose(ChatResponse response, SessionId session, string? requestModelId, out AuditEntry? entry, bool remember = true)
    {
        entry = null;
        if (!Enabled || LastAssistantText(response.Messages) is not { } target)
            return false;

        var now = _time.GetUtcNow();
        Mark(response.AdditionalProperties ??= [], string.IsNullOrWhiteSpace(response.ModelId) ? requestModelId : response.ModelId, now);

        var (notice, disclosed) = Decide(session, remember, now);
        if (notice is not null)
            target.Contents = [new TextContent(notice), .. target.Contents];
        entry = disclosed;
        return true;
    }

    /// <summary>
    /// Adds the machine-readable mark to <paramref name="properties"/>. An existing value is kept, except for
    /// <see cref="TransparencyKeys.Generated"/>.
    /// </summary>
    public void Mark(AdditionalPropertiesDictionary properties, string? modelId, DateTimeOffset now)
    {
        properties[TransparencyKeys.Generated] = BoxedTrue;
        if (!string.IsNullOrWhiteSpace(modelId))
            properties.TryAdd(TransparencyKeys.ModelId, modelId);
        properties.TryAdd(TransparencyKeys.GeneratedAt, now.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
        if (_pipelineName is not null)
            properties.TryAdd(TransparencyKeys.Pipeline, _pipelineName);
    }

    /// <summary>
    /// Records a disclosed reply for <paramref name="session"/> and returns the notice text to add, if any, and the
    /// audit entry when this is the session's first disclosure.
    /// </summary>
    public (string? Notice, AuditEntry? Entry) Decide(SessionId session, bool remember, DateTimeOffset now)
    {
        var first = !remember || Remember(session.Value, now);
        var noticeDue = _options.Transparency.NoticeMode switch
        {
            TransparencyNoticeMode.EveryReply => true,
            TransparencyNoticeMode.OncePerConversation => first,
            _ => false,
        };
        var notice = noticeDue ? NoticeText : null;
        return (notice, first ? Disclosed(session, notice is not null, now) : null);
    }

    private static ChatMessage? LastAssistantText(IList<ChatMessage> messages)
    {
        for (var i = messages.Count - 1; i >= 0; i--)
        {
            if (messages[i].Role == ChatRole.Assistant && !string.IsNullOrWhiteSpace(messages[i].Text))
                return messages[i];
        }
        return null;
    }

    /// <summary>Records the session as disclosed now; true when it was not known or had been idle too long.</summary>
    private bool Remember(string session, DateTimeOffset now)
    {
        var nowMs = now.ToUnixTimeMilliseconds();
        var idleMs = _options.SessionIdleTimeout.Ticks / TimeSpan.TicksPerMillisecond;
        bool first;
        while (true)
        {
            if (_sessions.TryAdd(session, nowMs))
            {
                first = true;
                break;
            }
            if (_sessions.TryGetValue(session, out var last) && _sessions.TryUpdate(session, nowMs, last))
            {
                first = nowMs - last > idleMs;
                break;
            }
        }

        SweepIdle(nowMs - idleMs);
        return first;
    }

    private void SweepIdle(long idleThresholdMs)
    {
        if ((Interlocked.Increment(ref _writeCount) & 255) != 0) return;
        foreach (var kvp in _sessions)
            if (kvp.Value < idleThresholdMs)
                _sessions.TryRemove(kvp);
    }

    private static AuditEntry Disclosed(SessionId session, bool withNotice, DateTimeOffset now) => new(
        Id: Guid.NewGuid().ToString("N"),
        Timestamp: now,
        Hash: string.Empty,
        PreviousHash: null,
        Severity: Severity.None,
        DetectorId: AuditEntryKinds.TransparencyDetectorId,
        Summary: withNotice ? MarkAndNoticeSummary : MarkSummary)
    {
        PolicyCode = AuditEntryKinds.DisclosedPolicyCode,
        SessionId = session.Value,
    };
}
