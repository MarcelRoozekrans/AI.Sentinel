using System.Buffers;
using System.Collections;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Redaction;

/// <summary>
/// Per-call redaction state: replaces detected values with numbered placeholders such as <c>[EMAIL_1_k3f9x2]</c>
/// and maps them back. Every session draws its own random tag, which every placeholder it mints carries, so a
/// placeholder from another call or another model round trip never resolves here and stays literal text; see
/// <see cref="PlaceholderFormat"/>. Originals are held in memory only and are never exposed through counts,
/// exceptions or <see cref="object.ToString"/>. Safe for concurrent use.
/// </summary>
internal sealed class RedactionSession
{
    private readonly IReadOnlyList<IRedactingDetector> _redactors;
    private readonly string _tag;

#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _gate = new();
#else
    private readonly object _gate = new();
#endif
    private readonly Dictionary<(string Type, string Value), string> _tokenByValue = new();
    private readonly Dictionary<string, string> _valueByToken = new(StringComparer.Ordinal);
    // Tokens whose value may go back into a tool call's arguments. A token is in here only when every
    // detector that produced its value allows it; see IRedactingDetector.RestoreIntoToolArguments.
    private readonly HashSet<string> _toolRestorable = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _nextByType = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, int>> _counts = new(StringComparer.Ordinal);

    /// <summary>A session with a new random tag. <paramref name="redactors"/> are asked for spans in this order,
    /// which also decides between two of them reporting the same span.</summary>
    public RedactionSession(IReadOnlyList<IRedactingDetector> redactors)
        : this(redactors, PlaceholderFormat.NewTag())
    {
    }

    /// <summary>A session with a fixed <paramref name="tag"/>, for tests that compare exact placeholders.</summary>
    internal RedactionSession(IReadOnlyList<IRedactingDetector> redactors, string tag)
    {
        ArgumentNullException.ThrowIfNull(redactors);
        ArgumentNullException.ThrowIfNull(tag);
        if (!PlaceholderFormat.IsTag(tag))
        {
            throw new ArgumentException("A placeholder tag is a lower-case letter followed by five lower-case letters or digits.", nameof(tag));
        }
        _redactors = redactors;
        _tag = tag;
    }

    /// <summary>Never prints the mapping.</summary>
    public override string ToString() => nameof(RedactionSession);

    public bool HasRedactions
    {
        get { lock (_gate) { return _valueByToken.Count > 0; } }
    }

    /// <summary>Every placeholder this session minted so far. Placeholders only, never values.</summary>
    public IReadOnlySet<string> MintedTokens
    {
        get { lock (_gate) { return new HashSet<string>(_valueByToken.Keys, StringComparer.Ordinal); } }
    }

    /// <summary>Detector id to entity type to number of redacted occurrences. Counts only, never values.</summary>
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> CountsByDetector
    {
        get
        {
            lock (_gate)
            {
                var snapshot = new Dictionary<string, IReadOnlyDictionary<string, int>>(_counts.Count, StringComparer.Ordinal);
                foreach (var (detector, byType) in _counts)
                {
                    snapshot[detector] = new Dictionary<string, int>(byType, StringComparer.Ordinal);
                }
                return snapshot;
            }
        }
    }

    public string Redact(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        // Detectors run outside the lock; any exception (including regex timeouts) propagates to the caller.
        var found = new List<Found>();
        for (var order = 0; order < _redactors.Count; order++)
        {
            var redactor = _redactors[order];
            var id = redactor.Id.Value;
            foreach (var span in redactor.FindSpans(text))
            {
                if (span.Start < 0 || span.Length <= 0 || span.Start > text.Length - span.Length)
                {
                    throw new InvalidOperationException(
                        $"Detector {id} reported a span outside the scanned text; refusing to redact with unreliable offsets.");
                }
                found.Add(new Found(span.Start, span.Length, NormalizeType(span.EntityType), id, redactor.RestoreIntoToolArguments, order, found.Count));
            }
        }

        if (found.Count == 0)
        {
            return text;
        }

        lock (_gate)
        {
            return ApplyLocked(text, found);
        }
    }

    private string ApplyLocked(string text, List<Found> found)
    {
        // A span over a placeholder this session minted is its own output, for example the value part of
        // `api_key=[API_KEY_1_k3f9x2]` echoed by a tool in this call: replacing it again would nest placeholders.
        found.RemoveAll(f => RedactionSpanCollector.PlaceholderAt(text, f.Start, f.Length) is { } token && _valueByToken.ContainsKey(token));
        if (found.Count == 0)
        {
            return text;
        }

        // Start, then longer first, then detector order, then the order the detector reported them. List.Sort is
        // unstable, so the last two keep the outcome the same on every run: of two detectors reporting the same
        // span, the earlier one types the placeholder and is credited.
        found.Sort(static (a, b) =>
        {
            if (a.Start != b.Start) return a.Start.CompareTo(b.Start);
            if (a.Length != b.Length) return b.Length.CompareTo(a.Length);
            if (a.DetectorOrder != b.DetectorOrder) return a.DetectorOrder.CompareTo(b.DetectorOrder);
            return a.Sequence.CompareTo(b.Sequence);
        });

        var sb = new StringBuilder(text.Length);
        var pos = 0;
        var i = 0;
        while (i < found.Count)
        {
            var winner = found[i];
            var start = winner.Start;
            var end = winner.Start + winner.Length;
            var toolRestorable = winner.ToolRestorable;
            i++;
            // Partial overlaps and containment merge into one union span typed by the longest original; of equally
            // long ones, the first in sort order.
            while (i < found.Count && found[i].Start < end)
            {
                var next = found[i];
                toolRestorable &= next.ToolRestorable;
                if (next.Length > winner.Length)
                {
                    winner = next;
                }
                end = Math.Max(end, next.Start + next.Length);
                i++;
            }

            sb.Append(text, pos, start - pos);
            sb.Append(TokenFor(winner.EntityType, text.Substring(start, end - start), toolRestorable));
            pos = end;
            Count(winner.DetectorId, winner.EntityType);
        }
        sb.Append(text, pos, text.Length - pos);
        return sb.ToString();
    }

    /// <summary>A request as the model will see it.</summary>
    /// <param name="Messages">Redacted copies of the messages.</param>
    /// <param name="Instructions">The redacted instructions, or the input when it had nothing to redact.</param>
    /// <param name="Placeholders">Every placeholder-shaped token in <paramref name="Messages"/> and
    /// <paramref name="Instructions"/>: this session's, and literals from other calls.</param>
    public readonly record struct RedactedRequest(
        IReadOnlyList<ChatMessage> Messages, string? Instructions, IReadOnlySet<string> Placeholders);

    /// <summary>
    /// Redacts every string of <paramref name="messages"/> that goes to the model, and <paramref name="instructions"/>,
    /// in one pass over copies, collecting the placeholder-shaped tokens of the result as it goes. The input is not
    /// mutated.
    /// </summary>
    public RedactedRequest RedactRequest(IReadOnlyList<ChatMessage> messages, string? instructions = null)
    {
        ArgumentNullException.ThrowIfNull(messages);
        var placeholders = new HashSet<string>(StringComparer.Ordinal);
        string Map(string text)
        {
            var redacted = Redact(text);
            CollectPlaceholders(redacted, placeholders);
            return redacted;
        }

        var result = new List<ChatMessage>(messages.Count);
        foreach (var message in messages)
        {
            result.Add(MapMessage(message, Map, redact: true));
        }
        return new RedactedRequest(result, instructions is null ? null : Map(instructions), placeholders);
    }

    /// <summary>Redacted copies of <paramref name="messages"/>; see <see cref="RedactRequest"/>.</summary>
    public IReadOnlyList<ChatMessage> Redact(IReadOnlyList<ChatMessage> messages) => RedactRequest(messages).Messages;

    /// <summary>Redacts a tool result before it goes to the model. Each value is converted and walked once.</summary>
    public object? RedactResult(object? result) => MapValue(result, Redact, redact: true);

    private static void CollectPlaceholders(string text, HashSet<string> into)
    {
        if (text.IndexOf('[', StringComparison.Ordinal) < 0)
        {
            return;
        }

        foreach (Match m in PlaceholderFormat.Pattern().Matches(text))
        {
            into.Add(m.Value);
        }
    }

    public string Restore(string text) => RestoreCore(text, toolArguments: false);

    /// <summary>Restores only the tokens whose value may go into a tool call's arguments.</summary>
    private string RestoreToolArgument(string text) => RestoreCore(text, toolArguments: true);

    private string RestoreCore(string text, bool toolArguments)
    {
        if (string.IsNullOrEmpty(text) || text.IndexOf('[', StringComparison.Ordinal) < 0)
        {
            return text;
        }

        return PlaceholderFormat.Pattern().Replace(text, m =>
        {
            lock (_gate)
            {
                // Only tokens this session minted are restored. One with another tag, from another call or
                // round trip, stays literal, and so does anything else.
                return _valueByToken.TryGetValue(m.Value, out var original)
                    && (!toolArguments || _toolRestorable.Contains(m.Value))
                    ? original
                    : m.Value;
            }
        });
    }

    /// <summary>
    /// Restores a response for the caller, who owns the values: text, reasoning and tool results get every
    /// value back. A tool call answered by a result that FOLLOWS it in the same list is history and gets every
    /// value back too. Any other call may still be invoked, by a function-invoking client above Sentinel, so it
    /// follows the tool rule and keeps the placeholders of values that must never reach a tool argument.
    /// Matching is positional because providers reuse call ids, for example <c>call_0</c> on every turn: an
    /// earlier answered call must not make a later unanswered one with the same id look answered. A call with
    /// an empty id is never answered.
    /// </summary>
    /// <remarks>
    /// With Sentinel inside function invocation, such a kept placeholder is a literal in the next round trip,
    /// which is redacted by a fresh session with another tag, so the value it stood for gets another token there
    /// and the kept one never resolves. The mapping is deliberately not kept across round trips; nothing leaks,
    /// the model just sees two names.
    /// </remarks>
    public IList<ChatMessage> Restore(IList<ChatMessage> messages)
    {
        var contents = new List<IList<AIContent>>(messages.Count);
        foreach (var message in messages)
        {
            contents.Add(message.Contents);
        }
        var answered = AnsweredCalls(contents);
        var result = new List<ChatMessage>(messages.Count);
        foreach (var message in messages)
        {
            result.Add(MapMessage(message, Restore, redact: false, answered));
        }
        return result;
    }

    /// <summary>
    /// Restores streamed updates for the caller by the rules of <see cref="Restore(IList{ChatMessage})"/>: text,
    /// reasoning and tool results get every value back, a call answered by a result streamed after it is
    /// history, and any other call keeps the placeholders of values that must never reach a tool argument.
    /// A placeholder can be split across updates, such as <c>[EMA</c> and <c>IL_1_k3f9x2]</c>, so text that ends in
    /// what may be the start of one is held back and put in front of the next text of the same kind in the
    /// same message. Text still held when its message or the stream ends is no placeholder: it is released,
    /// as it was, into the last text content of that kind seen in that message, so it is never lost or
    /// duplicated. Messages are delimited exactly as <see cref="ChatResponseExtensions.ToChatResponse(IEnumerable{ChatResponseUpdate})"/>
    /// delimits them, which is what the response scan saw. No update carries part of a placeholder.
    /// Returns copies: the count, the update metadata and all other content stay as they were, and the input
    /// is not mutated.
    /// </summary>
    public IReadOnlyList<ChatResponseUpdate> RestoreUpdates(IReadOnlyList<ChatResponseUpdate> updates)
    {
        var lists = new List<IList<AIContent>>(updates.Count);
        foreach (var update in updates)
        {
            lists.Add(update.Contents);
        }
        var answered = AnsweredCalls(lists);

        var restorer = new UpdateRestorer(this, answered, LongestToken());
        var messages = new MessageBoundaries();
        var result = new List<ChatResponseUpdate>(updates.Count);
        foreach (var update in updates)
        {
            // A placeholder never spans two messages, so text is never held across into another one.
            if (messages.StartsNewMessage(update))
            {
                restorer.ReleaseHeld();
            }
            result.Add(restorer.Restore(update));
        }
        restorer.ReleaseHeld();
        return result;
    }

    /// <summary>Restores the updates of one stream in order, holding text back across them.</summary>
    private sealed class UpdateRestorer(RedactionSession session, HashSet<FunctionCallContent> answered, int longestToken)
    {
        private readonly StreamedText _text = new(session, longestToken);
        private readonly StreamedText _reasoning = new(session, longestToken);
        private TextContent? _lastText;
        private TextReasoningContent? _lastReasoning;

        public ChatResponseUpdate Restore(ChatResponseUpdate update)
        {
            var contents = new List<AIContent>(update.Contents.Count);
            foreach (var content in update.Contents)
            {
                switch (content)
                {
                    case TextContent t:
                        _lastText = CopyMetadata(t, new TextContent(_text.Restore(t.Text)));
                        contents.Add(_lastText);
                        break;
                    case TextReasoningContent r:
                        _lastReasoning = CopyMetadata(r, new TextReasoningContent(_reasoning.Restore(r.Text))
                        {
                            ProtectedData = r.ProtectedData,
                        });
                        contents.Add(_lastReasoning);
                        break;
                    default:
                        contents.Add(session.MapContent(content, session.Restore, redact: false, answered));
                        break;
                }
            }
            var copy = update.Clone();
            copy.Contents = contents;
            return copy;
        }

        // Held text is no placeholder: it never got its closing bracket. It is released, as it was, into the last
        // text content of its kind, which belongs to the message that just ended; the next text starts empty.
        public void ReleaseHeld()
        {
            if (_lastText is not null)
            {
                _lastText.Text += _text.TakeHeld();
            }
            if (_lastReasoning is not null)
            {
                _lastReasoning.Text += _reasoning.TakeHeld();
            }
        }
    }

    /// <summary>
    /// Tells where a new message starts in a stream, the way <c>ToChatResponse</c> groups updates: a new message
    /// starts when a non-empty message id or author name differs from the current message's, or when a role is
    /// given that differs from the current message's role, which is assistant until one is given. Empty ids and
    /// authors and a missing role continue the current message; a non-empty value is adopted by it.
    /// </summary>
    private sealed class MessageBoundaries
    {
        private bool _started;
        private string? _id;
        private string? _author;
        private ChatRole _role;

        public bool StartsNewMessage(ChatResponseUpdate update)
        {
            var isNew = !_started
                || Differs(update.MessageId, _id)
                || Differs(update.AuthorName, _author)
                || (update.Role is { } role && role != _role);
            if (isNew)
            {
                _started = true;
                _id = null;
                _author = null;
                _role = ChatRole.Assistant;
            }

            if (!string.IsNullOrEmpty(update.MessageId))
            {
                _id = update.MessageId;
            }
            if (!string.IsNullOrEmpty(update.AuthorName))
            {
                _author = update.AuthorName;
            }
            if (update.Role is { } given)
            {
                _role = given;
            }
            return isNew;
        }

        private static bool Differs(string? value, string? current) =>
            !string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(current) && !string.Equals(value, current, StringComparison.Ordinal);
    }

    private int LongestToken()
    {
        lock (_gate)
        {
            var longest = 0;
            foreach (var token in _valueByToken.Keys)
            {
                longest = Math.Max(longest, token.Length);
            }
            return longest;
        }
    }

    /// <summary>One kind of streamed text, restored piece by piece, holding back a possible placeholder start.</summary>
    private sealed class StreamedText(RedactionSession session, int longestToken)
    {
        private string Held { get; set; } = string.Empty;

        public string TakeHeld()
        {
            var held = Held;
            Held = string.Empty;
            return held;
        }

        public string? Restore(string? text)
        {
            if (Held.Length == 0 && text is null)
            {
                return null;
            }

            var joined = Held + text;
            var cut = HoldFrom(joined);
            Held = joined[cut..];
            return session.Restore(joined[..cut]);
        }

        // The start of an unterminated '[' followed only by placeholder characters, letters of either case because
        // of the tag, and shorter than the longest
        // token this session minted, so it may still become one; otherwise the end of the text.
        private int HoldFrom(string text)
        {
            var open = text.LastIndexOf('[');
            if (open < 0 || text.Length - open >= longestToken)
            {
                return text.Length;
            }

            for (var i = open + 1; i < text.Length; i++)
            {
                if (!char.IsAsciiLetter(text[i]) && !char.IsAsciiDigit(text[i]) && text[i] != '_')
                {
                    return text.Length;
                }
            }
            return open;
        }
    }

    /// <summary>
    /// Returns a new <see cref="AIFunctionArguments"/> with the real values restored, except values whose
    /// detector forbids restoring them into tool arguments, which keep their placeholder. Keyed by
    /// <paramref name="comparer"/>. The input and any dictionary or list nested in it are never mutated,
    /// because the input can be backed by the arguments of a function call kept in the chat history, which
    /// must keep the placeholders. Context and Services are copied. <see cref="AIFunctionArguments"/> does not
    /// expose its comparer, so the caller passes the one of the dictionary it was built from.
    /// </summary>
    public AIFunctionArguments Restore(AIFunctionArguments args, IEqualityComparer<string> comparer)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(comparer);

        var restored = new AIFunctionArguments(comparer)
        {
            Context = args.Context,
            Services = args.Services,
        };
        foreach (var (key, value) in args)
        {
            if (restored.ContainsKey(key))
            {
                throw new InvalidOperationException(
                    "Two argument names are identical under the given comparer; refusing to drop one.");
            }
            restored[key] = MapValue(value, RestoreToolArgument, redact: false);
        }
        return restored;
    }

    private static IEqualityComparer<string> ComparerOf(IDictionary<string, object?> source) =>
        source is Dictionary<string, object?> dictionary ? dictionary.Comparer : StringComparer.Ordinal;

    private string TokenFor(string type, string value, bool toolRestorable)
    {
        if (_tokenByValue.TryGetValue((type, value), out var existing))
        {
            if (!toolRestorable)
            {
                _toolRestorable.Remove(existing);
            }
            return existing;
        }

        _nextByType.TryGetValue(type, out var n);
        n = Math.Max(n, 1);
        if (n == int.MaxValue)
        {
            throw new InvalidOperationException($"Placeholder counter for entity type {type} is exhausted.");
        }
        _nextByType[type] = n + 1;
        var token = PlaceholderFormat.Format(type, n, _tag);
        _tokenByValue[(type, value)] = token;
        _valueByToken[token] = value;
        if (toolRestorable)
        {
            _toolRestorable.Add(token);
        }
        return token;
    }

    private void Count(string detectorId, string type)
    {
        if (!_counts.TryGetValue(detectorId, out var byType))
        {
            byType = new Dictionary<string, int>(StringComparer.Ordinal);
            _counts[detectorId] = byType;
        }
        byType.TryGetValue(type, out var count);
        byType[type] = count + 1;
    }

    private static string NormalizeType(string? entityType)
    {
        if (string.IsNullOrEmpty(entityType))
        {
            return "UNKNOWN";
        }

        var chars = entityType.ToUpperInvariant().ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (!(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_'))
            {
                chars[i] = '_';
            }
        }
        return new string(chars);
    }

    // Walks backwards collecting the ids of results seen so far, so a call counts as answered only when a
    // result with its id comes after it. One content list per message, or per streamed update.
    private static HashSet<FunctionCallContent> AnsweredCalls(List<IList<AIContent>> lists)
    {
        var answered = new HashSet<FunctionCallContent>(ReferenceEqualityComparer.Instance);
        var laterResults = new HashSet<string>(StringComparer.Ordinal);
        for (var m = lists.Count - 1; m >= 0; m--)
        {
            var contents = lists[m];
            for (var c = contents.Count - 1; c >= 0; c--)
            {
                switch (contents[c])
                {
                    case FunctionResultContent fr when !string.IsNullOrEmpty(fr.CallId):
                        laterResults.Add(fr.CallId);
                        break;
                    case FunctionCallContent call when !string.IsNullOrEmpty(call.CallId) && laterResults.Contains(call.CallId):
                        answered.Add(call);
                        break;
                }
            }
        }
        return answered;
    }

    private ChatMessage MapMessage(ChatMessage message, Func<string, string> map, bool redact, HashSet<FunctionCallContent>? answered = null)
    {
        var copy = message.Clone();
        var contents = new List<AIContent>(message.Contents.Count);
        foreach (var content in message.Contents)
        {
            contents.Add(MapContent(content, map, redact, answered));
        }
        copy.Contents = contents;
        return copy;
    }

    // answered: the calls followed by their result in the list being restored; null when redacting, or for
    // content nested in a value, which follows the tool rule.
    private AIContent MapContent(AIContent content, Func<string, string> map, bool redact, HashSet<FunctionCallContent>? answered = null)
    {
        switch (content)
        {
            case TextContent text:
                return CopyMetadata(text, new TextContent(text.Text is null ? null : map(text.Text)));
            case FunctionCallContent call:
                // Arguments of a call that may still be invoked are what a tool would receive, so restoring
                // them follows the tool rule; an answered call is history and is restored like text.
                var restoreAll = redact || (answered is not null && answered.Contains(call));
                return CopyMetadata(call, MapCall(call, restoreAll ? map : RestoreToolArgument, redact));
            case FunctionResultContent fr:
                return CopyMetadata(fr, new FunctionResultContent(fr.CallId, MapValue(fr.Result, map, redact))
                {
                    Exception = fr.Exception,
                });
            case TextReasoningContent reasoning:
                return CopyMetadata(reasoning, new TextReasoningContent(reasoning.Text is null ? null : map(reasoning.Text))
                {
                    ProtectedData = reasoning.ProtectedData,
                });
            case ToolApprovalRequestContent request when request.ToolCall is FunctionCallContent call:
                return CopyApprovalRequest(request, MapApprovalCall(call, map, redact));
            case ToolApprovalResponseContent response when response.ToolCall is FunctionCallContent call:
                return CopyMetadata(response, new ToolApprovalResponseContent(response.RequestId, response.Approved, MapApprovalCall(call, map, redact))
                {
                    Reason = response.Reason is null ? null : map(response.Reason),
                });
            case DataContent data when redact && IsText(data) && !data.Data.IsEmpty:
                var encoding = EncodingOf(data);
                var mapped = encoding.GetBytes(map(encoding.GetString(data.Data.Span)));
                return CopyMetadata(data, new DataContent(mapped, data.MediaType) { Name = data.Name });
            default:
                return content;
        }
    }

    private static Encoding EncodingOf(DataContent data)
    {
        var parameters = data.MediaType.Split(';');
        for (var i = 1; i < parameters.Length; i++)
        {
            var parameter = parameters[i].Trim();
            if (!parameter.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var name = parameter["charset=".Length..].Trim('"', ' ');
            Encoding? encoding = null;
            try
            {
                encoding = Encoding.GetEncoding(name);
            }
            catch (ArgumentException)
            {
                encoding = null;
            }

            return encoding ?? throw new InvalidOperationException(
                "Text data content declares a charset that is not supported, so it cannot be scanned.");
        }
        return Encoding.UTF8;
    }

    // Text and the text-based application types a model reads as text: JSON, XML and their +json and +xml
    // variants, NDJSON, YAML, JavaScript and form data. Parameters such as charset are ignored here.
    private static bool IsText(DataContent data)
    {
        var mediaType = data.MediaType.AsSpan();
        var semicolon = mediaType.IndexOf(';');
        if (semicolon >= 0)
        {
            mediaType = mediaType[..semicolon];
        }
        mediaType = mediaType.Trim();

        if (mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!mediaType.StartsWith("application/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var subtype = mediaType["application/".Length..];
        foreach (var textual in TextApplicationSubtypes)
        {
            if (subtype.Equals(textual, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return subtype.EndsWith("+json", StringComparison.OrdinalIgnoreCase)
            || subtype.EndsWith("+xml", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] TextApplicationSubtypes =
        ["json", "xml", "x-ndjson", "yaml", "x-yaml", "javascript", "x-www-form-urlencoded"];

    // The call inside an approval request or response: redacted like any call on the way to the model. On the way
    // back it is a call that runs once approved, so it follows the tool rule whether or not a result follows it.
    private FunctionCallContent MapApprovalCall(FunctionCallContent call, Func<string, string> map, bool redact) =>
        CopyMetadata(call, MapCall(call, redact ? map : RestoreToolArgument, redact));

    /// <summary>
    /// A copy of <paramref name="request"/> carrying <paramref name="call"/>. The request is copied through its
    /// JSON contract, which carries every property, including RequiresConfirmation, which is experimental and so
    /// is not set from code here; the copy's call is then given the mapped arguments and the call's metadata.
    /// </summary>
    private static ToolApprovalRequestContent CopyApprovalRequest(ToolApprovalRequestContent request, FunctionCallContent call)
    {
        // The type info comes from MEAI's own source-generated contract, so the copy works under trimming and AOT.
        var contentInfo = AIJsonUtilities.DefaultOptions.GetTypeInfo(typeof(AIContent));
        var json = JsonSerializer.SerializeToElement(request, contentInfo);
        if (json.Deserialize(contentInfo) is not ToolApprovalRequestContent { ToolCall: FunctionCallContent copiedCall } copy)
        {
            throw new InvalidOperationException("A tool approval request could not be copied for redaction.");
        }

        copiedCall.Arguments = call.Arguments;
        copiedCall.Exception = call.Exception;
        copiedCall.InformationalOnly = call.InformationalOnly;
        CopyMetadata(call, copiedCall);
        return CopyMetadata(request, copy);
    }

    private FunctionCallContent MapCall(FunctionCallContent call, Func<string, string> map, bool redact)
    {
        IDictionary<string, object?>? args = null;
        if (call.Arguments is not null)
        {
            var mapped = new Dictionary<string, object?>(call.Arguments.Count, ComparerOf(call.Arguments));
            foreach (var (key, value) in call.Arguments)
            {
                mapped[key] = MapValue(value, map, redact);
            }
            args = mapped;
        }
        return new FunctionCallContent(call.CallId, call.Name, args)
        {
            Exception = call.Exception,
            InformationalOnly = call.InformationalOnly,
        };
    }

    private static T CopyMetadata<T>(AIContent source, T target) where T : AIContent
    {
        target.AdditionalProperties = source.AdditionalProperties;
        target.Annotations = source.Annotations;
        target.RawRepresentation = source.RawRepresentation;
        return target;
    }

    private object? MapValue(object? value, Func<string, string> map, bool redact)
    {
        switch (value)
        {
            case null:
                return null;
            case string s:
                return map(s);
            case JsonElement e:
                return MapJson(e, map);
            case JsonNode node:
                var nodeElement = MapJson(JsonElementOf(node), map);
                return redact ? nodeElement : JsonNode.Parse(nodeElement.GetRawText());
            case AIContent content:
                return MapContent(content, map, redact);
            case IDictionary<string, object?> dict:
                return MapDictionary(dict, map, redact);
            case IEnumerable<AIContent> contents:
                return MapContents(contents, map, redact);
            case char[] chars when redact:
                return map(new string(chars)).ToCharArray();
            case Array array when array.GetType().GetElementType()!.IsPrimitive:
                return value; // binary or numeric data, not text
            // Typed collections such as List<string> or string[] are not restored in arguments: model-parsed
            // arguments arrive as JsonElement or object containers.
            case IList list when redact || value is object[] or List<object?>:
                return MapList(list, map, redact);
            default:
                return redact && !IsPrimitive(value) ? MapJson(ToJson(value), map) : value;
        }
    }

    private Dictionary<string, object?> MapDictionary(IDictionary<string, object?> dict, Func<string, string> map, bool redact)
    {
        var result = new Dictionary<string, object?>(dict.Count, ComparerOf(dict));
        foreach (var (key, item) in dict)
        {
            if (!result.TryAdd(map(key), MapValue(item, map, redact)))
            {
                throw new InvalidOperationException("Mapping made two names identical.");
            }
        }
        return result;
    }

    private List<AIContent> MapContents(IEnumerable<AIContent> contents, Func<string, string> map, bool redact)
    {
        var result = new List<AIContent>();
        foreach (var content in contents)
        {
            result.Add(MapContent(content, map, redact));
        }
        return result;
    }

    private object MapList(IList list, Func<string, string> map, bool redact)
    {
        var result = new List<object?>(list.Count);
        foreach (var item in list)
        {
            result.Add(MapValue(item, map, redact));
        }
        return list is object[]? result.ToArray() : result;
    }

    private static bool IsPrimitive(object value)
    {
        var type = value.GetType();
        return type.IsPrimitive || type.IsEnum
            || value is decimal or DateTime or DateTimeOffset or TimeSpan or Guid;
    }

    private static JsonElement JsonElementOf(JsonNode node)
    {
        using var document = JsonDocument.Parse(node.ToJsonString());
        return document.RootElement.Clone();
    }

    private static JsonElement ToJson(object value)
    {
        JsonElement? serialized = null;
        try
        {
            // GetTypeInfo resolves through the options' resolver: reflection where it is enabled, and under native
            // AOT a type no source-generated context covers throws here, which fails the call closed below.
            serialized = JsonSerializer.SerializeToElement(value, AIJsonUtilities.DefaultOptions.GetTypeInfo(value.GetType()));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Deliberately not chained: serializer and getter messages can echo paths and parts of the value.
            serialized = null;
        }

        return serialized
            ?? throw new InvalidOperationException(
                $"A value of type {value.GetType().FullName} could not be serialized for redaction.");
    }

    private static JsonElement MapJson(JsonElement element, Func<string, string> map)
    {
        if (element.ValueKind == JsonValueKind.Undefined)
        {
            return element;
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            WriteMapped(writer, element, map);
        }
        using var doc = JsonDocument.Parse(buffer.WrittenMemory);
        return doc.RootElement.Clone();
    }

    private static void WriteMapped(Utf8JsonWriter writer, JsonElement element, Func<string, string> map)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                writer.WriteStringValue(map(element.GetString()!));
                break;
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(map(property.Name));
                    WriteMapped(writer, property.Value, map);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteMapped(writer, item, map);
                }
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private readonly record struct Found(int Start, int Length, string EntityType, string DetectorId, bool ToolRestorable, int DetectorOrder, int Sequence);
}
