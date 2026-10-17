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
    /// Removes Sentinel's own notice from the history: the notice text at the start of the first
    /// <see cref="TextContent"/> of an assistant message. That is where Sentinel put it, as its own leading text,
    /// or, once an app folds streamed updates into a message, joined with the reply's text that followed it.
    /// Other roles and notice text in any other position are left alone. The caller's messages are not mutated; a
    /// changed message is a copy.
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
                || FirstText(message.Contents) is not { } first
                || !first.Text.StartsWith(notice, StringComparison.Ordinal))
            {
                continue;
            }

            stripped ??= new List<ChatMessage>(messages);
            stripped[i] = WithoutNotice(message, first, notice.Length);
        }
        return stripped ?? messages;
    }

    private static TextContent? FirstText(IList<AIContent> contents)
    {
        foreach (var content in contents)
        {
            if (content is TextContent text)
                return text;
        }
        return null;
    }

    // The text the notice was joined with keeps its metadata; a text that held only the notice is removed.
    private static ChatMessage WithoutNotice(ChatMessage message, TextContent text, int noticeLength)
    {
        var contents = new List<AIContent>(message.Contents);
        var index = contents.IndexOf(text);
        if (text.Text.Length == noticeLength)
        {
            contents.RemoveAt(index);
        }
        else
        {
            contents[index] = new TextContent(text.Text[noticeLength..])
            {
                AdditionalProperties = text.AdditionalProperties,
                Annotations = text.Annotations,
                RawRepresentation = text.RawRepresentation,
            };
        }
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
    /// Discloses a streamed reply by the rules of <see cref="TryDisclose(ChatResponse, SessionId, string?, out AuditEntry?, bool)"/>.
    /// The mark goes on the first update without a message id, whose properties <c>ToChatResponse</c> merges into the
    /// response it builds, or on the first update when every update has a message id; its message then carries it.
    /// A key the inner client set in the same scope is kept, except for <see cref="TransparencyKeys.Generated"/>,
    /// which is set wherever it appears in that scope so that no later update undoes it.
    /// The notice is a new leading <see cref="TextContent"/> in the first update with text of the last assistant
    /// message with text, messages delimited as <c>ToChatResponse</c> delimits them.
    /// </summary>
    /// <param name="updates">The streamed reply, after the response scan and redaction restore.</param>
    /// <param name="session">The call's session.</param>
    /// <param name="requestModelId">The requested model, used when no update names one.</param>
    /// <param name="disclosed">The updates to return: the same count and metadata, with the changed updates
    /// copied. <paramref name="updates"/> is not mutated.</param>
    /// <param name="entry">The entry to append, or <see langword="null"/> when the session was already disclosed.</param>
    /// <param name="remember">As for the non-streaming overload.</param>
    /// <returns>True when the reply was marked.</returns>
    public bool TryDisclose(
        IReadOnlyList<ChatResponseUpdate> updates,
        SessionId session,
        string? requestModelId,
        out IReadOnlyList<ChatResponseUpdate> disclosed,
        out AuditEntry? entry,
        bool remember = true)
    {
        disclosed = updates;
        entry = null;
        if (!Enabled || NoticeTarget(updates) is not { } target)
            return false;

        var now = _time.GetUtcNow();
        var copies = new ChatResponseUpdate?[updates.Count];
        Mark(updates, copies, ModelIdOf(updates) ?? requestModelId, now);

        var (notice, first) = Decide(session, remember, now);
        if (notice is not null)
        {
            var update = Own(updates, copies, target);
            update.Contents = [new TextContent(notice), .. update.Contents];
        }

        var result = new ChatResponseUpdate[updates.Count];
        for (var i = 0; i < result.Length; i++)
            result[i] = copies[i] ?? updates[i];
        disclosed = result;
        entry = first;
        return true;
    }

    /// <summary>
    /// Adds the machine-readable mark to <paramref name="properties"/>. An existing value is kept, except for
    /// <see cref="TransparencyKeys.Generated"/>.
    /// </summary>
    public void Mark(AdditionalPropertiesDictionary properties, string? modelId, DateTimeOffset now)
    {
        properties[TransparencyKeys.Generated] = BoxedTrue;
        foreach (var (key, value) in MarkValues(modelId, now))
            properties.TryAdd(key, value);
    }

    // The mark's keys other than Generated, which is always set.
    private List<KeyValuePair<string, object?>> MarkValues(string? modelId, DateTimeOffset now)
    {
        var values = new List<KeyValuePair<string, object?>>(3);
        if (!string.IsNullOrWhiteSpace(modelId))
            values.Add(new(TransparencyKeys.ModelId, modelId));
        values.Add(new(TransparencyKeys.GeneratedAt, now.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)));
        if (_pipelineName is not null)
            values.Add(new(TransparencyKeys.Pipeline, _pipelineName));
        return values;
    }

    // ToChatResponse (MEAI 10.11) scopes an update's properties to the response when the update has no message id
    // and to that update's message when it has one. The mark goes on the first update without a message id, so the
    // response carries it. When every update has a message id no update reaches the response, and the mark goes on
    // the first update, so its message carries it. Values set in the same scope are the ones checked and kept.
    private void Mark(IReadOnlyList<ChatResponseUpdate> updates, ChatResponseUpdate?[] copies, string? modelId, DateTimeOffset now)
    {
        var at = 0;
        for (var i = 0; i < updates.Count; i++)
        {
            if (string.IsNullOrEmpty(updates[i].MessageId))
            {
                at = i;
                break;
            }
        }
        var scope = updates[at].MessageId;

        var properties = Own(updates, copies, at).AdditionalProperties ??= [];
        properties[TransparencyKeys.Generated] = BoxedTrue;
        for (var i = at + 1; i < updates.Count; i++)
        {
            if (SameScope(updates[i], scope) && updates[i].AdditionalProperties?.ContainsKey(TransparencyKeys.Generated) == true)
                Own(updates, copies, i).AdditionalProperties![TransparencyKeys.Generated] = BoxedTrue;
        }

        foreach (var (key, value) in MarkValues(modelId, now))
        {
            if (!SetInScope(updates, scope, key))
                properties[key] = value;
        }
    }

    private static bool SameScope(ChatResponseUpdate update, string? scope) =>
        string.IsNullOrEmpty(scope)
            ? string.IsNullOrEmpty(update.MessageId)
            : string.Equals(update.MessageId, scope, StringComparison.Ordinal);

    private static bool SetInScope(IReadOnlyList<ChatResponseUpdate> updates, string? scope, string key)
    {
        foreach (var update in updates)
        {
            if (SameScope(update, scope) && update.AdditionalProperties?.ContainsKey(key) == true)
                return true;
        }
        return false;
    }

    // A copy of update i that may be changed, made once: its contents and properties are copies too.
    private static ChatResponseUpdate Own(IReadOnlyList<ChatResponseUpdate> updates, ChatResponseUpdate?[] copies, int i)
    {
        if (copies[i] is { } owned)
            return owned;

        var source = updates[i];
        var copy = source.Clone();
        copy.Contents = new List<AIContent>(source.Contents);
        if (source.AdditionalProperties is { } properties)
            copy.AdditionalProperties = new AdditionalPropertiesDictionary(properties);
        copies[i] = copy;
        return copy;
    }

    // The model that answered, as ToChatResponse reports it: the last model id an update names.
    private static string? ModelIdOf(IReadOnlyList<ChatResponseUpdate> updates)
    {
        for (var i = updates.Count - 1; i >= 0; i--)
        {
            if (!string.IsNullOrWhiteSpace(updates[i].ModelId))
                return updates[i].ModelId;
        }
        return null;
    }

    /// <summary>
    /// The index of the first update with text of the last assistant message whose text the person sees, or
    /// <see langword="null"/> when no assistant message has any.
    /// </summary>
    private static int? NoticeTarget(IReadOnlyList<ChatResponseUpdate> updates)
    {
        var boundaries = new StreamMessageBoundaries();
        int? target = null;
        int? firstText = null;
        var hasText = false;
        var role = ChatRole.Assistant;
        for (var i = 0; i < updates.Count; i++)
        {
            if (boundaries.StartsNewMessage(updates[i]))
            {
                if (hasText && role == ChatRole.Assistant)
                    target = firstText;
                firstText = null;
                hasText = false;
            }
            role = boundaries.Role;

            foreach (var content in updates[i].Contents)
            {
                if (content is not TextContent text)
                    continue;
                firstText ??= i;
                hasText |= !string.IsNullOrWhiteSpace(text.Text);
            }
        }
        return hasText && role == ChatRole.Assistant ? firstText : target;
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

    /// <summary>
    /// Forgets the disclosure <paramref name="entry"/> recorded, when it could not be written: the reply that
    /// carried it never reached the caller, so the session's next reply is disclosed as its first. Only the claim
    /// that produced this entry is removed; a later reply's claim is kept.
    /// </summary>
    public void Retract(AuditEntry entry)
    {
        if (entry.SessionId is { } session)
            _sessions.TryRemove(new KeyValuePair<string, long>(session, entry.Timestamp.ToUnixTimeMilliseconds()));
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
