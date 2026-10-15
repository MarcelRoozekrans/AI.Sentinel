using System.Buffers;
using System.Collections;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Redaction;

/// <summary>
/// Per-call redaction state: replaces detected values with numbered placeholders such as <c>[EMAIL_1]</c>
/// and maps them back. Originals are held in memory only and are never exposed through counts,
/// exceptions or <see cref="object.ToString"/>. Safe for concurrent use.
/// </summary>
internal sealed partial class RedactionSession(IReadOnlyList<IRedactingDetector> redactors)
{
    // Reserved numbers above this cap are ignored so a hostile literal cannot push counters towards overflow.
    private const int MaxReservedNumber = 1_000_000;

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

    [GeneratedRegex(@"\[(?<type>[A-Z0-9_]+)_(?<n>\d+)\]", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PlaceholderPattern();

    /// <summary>Never prints the mapping.</summary>
    public override string ToString() => nameof(RedactionSession);

    public bool HasRedactions
    {
        get { lock (_gate) { return _valueByToken.Count > 0; } }
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

    public string Redact(string text) => RedactCore(EscapeLiterals(text));

    private string RedactCore(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        // Detectors run outside the lock; any exception (including regex timeouts) propagates to the caller.
        var found = new List<Found>();
        foreach (var redactor in redactors)
        {
            var id = redactor.Id.Value;
            foreach (var span in redactor.FindSpans(text))
            {
                if (span.Start < 0 || span.Length <= 0 || span.Start > text.Length - span.Length)
                {
                    throw new InvalidOperationException(
                        $"Detector {id} reported a span outside the scanned text; refusing to redact with unreliable offsets.");
                }
                found.Add(new Found(span.Start, span.Length, NormalizeType(span.EntityType), id, redactor.RestoreIntoToolArguments));
            }
        }

        lock (_gate)
        {
            if (found.Count == 0)
            {
                return text;
            }

            return ApplyLocked(text, found);
        }
    }

    private string ApplyLocked(string text, List<Found> found)
    {
        found.Sort(static (a, b) =>
        {
            var byStart = a.Start.CompareTo(b.Start);
            return byStart != 0 ? byStart : b.Length.CompareTo(a.Length);
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
            // Partial overlaps and containment merge into one union span typed by the longest original.
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

    public IReadOnlyList<ChatMessage> Redact(IReadOnlyList<ChatMessage> messages)
    {
        // Pass 1 reserves every placeholder-shaped literal in the whole request so no minted token can collide.
        // Pass 2 swaps literals that equal an already minted token for fresh tokens that restore to the literal.
        // Pass 3 redacts.
        foreach (var message in messages)
        {
            MapMessage(message, Reserve, redact: true);
        }

        var escaped = new List<ChatMessage>(messages.Count);
        foreach (var message in messages)
        {
            escaped.Add(MapMessage(message, EscapeLiterals, redact: true));
        }

        var result = new List<ChatMessage>(escaped.Count);
        foreach (var message in escaped)
        {
            result.Add(MapMessage(message, RedactCore, redact: true));
        }
        return result;
    }

    public object? RedactResult(object? result)
    {
        MapValue(result, Reserve, redact: true);
        var escaped = MapValue(result, EscapeLiterals, redact: true);
        return MapValue(escaped, RedactCore, redact: true);
    }

    private string Reserve(string text)
    {
        lock (_gate)
        {
            ReserveExistingPlaceholders(text);
        }
        return text;
    }

    private string EscapeLiterals(string text)
    {
        if (string.IsNullOrEmpty(text) || text.IndexOf('[', StringComparison.Ordinal) < 0)
        {
            return text;
        }

        lock (_gate)
        {
            ReserveExistingPlaceholders(text);
            return PlaceholderPattern().Replace(text, m =>
                _valueByToken.ContainsKey(m.Value) ? TokenFor(m.Groups["type"].Value, m.Value, toolRestorable: true) : m.Value);
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

        return PlaceholderPattern().Replace(text, m =>
        {
            lock (_gate)
            {
                // Only tokens this session created are restored; anything else stays literal.
                return _valueByToken.TryGetValue(m.Value, out var original)
                    && (!toolArguments || _toolRestorable.Contains(m.Value))
                    ? original
                    : m.Value;
            }
        });
    }

    public IList<ChatMessage> Restore(IList<ChatMessage> messages)
    {
        var result = new List<ChatMessage>(messages.Count);
        foreach (var message in messages)
        {
            result.Add(MapMessage(message, Restore, redact: false));
        }
        return result;
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
        var token = $"[{type}_{n.ToString(CultureInfo.InvariantCulture)}]";
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

    private void ReserveExistingPlaceholders(string text)
    {
        if (text.IndexOf('[', StringComparison.Ordinal) < 0)
        {
            return;
        }

        foreach (Match m in PlaceholderPattern().Matches(text))
        {
            if (!int.TryParse(m.Groups["n"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n > MaxReservedNumber)
            {
                continue;
            }
            var type = m.Groups["type"].Value;
            _nextByType.TryGetValue(type, out var current);
            if (n + 1 > current)
            {
                _nextByType[type] = n + 1;
            }
        }
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

    private ChatMessage MapMessage(ChatMessage message, Func<string, string> map, bool redact)
    {
        var copy = message.Clone();
        var contents = new List<AIContent>(message.Contents.Count);
        foreach (var content in message.Contents)
        {
            contents.Add(MapContent(content, map, redact));
        }
        copy.Contents = contents;
        return copy;
    }

    private AIContent MapContent(AIContent content, Func<string, string> map, bool redact)
    {
        switch (content)
        {
            case TextContent text:
                return CopyMetadata(text, new TextContent(text.Text is null ? null : map(text.Text)));
            case FunctionCallContent call:
                // Arguments of a call are what a tool would receive, so restoring them follows the tool rule.
                return CopyMetadata(call, MapCall(call, redact ? map : RestoreToolArgument, redact));
            case FunctionResultContent fr when redact:
                return CopyMetadata(fr, new FunctionResultContent(fr.CallId, MapValue(fr.Result, map, redact))
                {
                    Exception = fr.Exception,
                });
            case TextReasoningContent reasoning when redact:
                return CopyMetadata(reasoning, new TextReasoningContent(reasoning.Text is null ? null : map(reasoning.Text))
                {
                    ProtectedData = reasoning.ProtectedData,
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

    private static bool IsText(DataContent data) =>
        data.MediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase);

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
                var nodeElement = MapJson(JsonSerializer.SerializeToElement(node, AIJsonUtilities.DefaultOptions), map);
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
        return list is object[] ? result.ToArray() : result;
    }

    private static bool IsPrimitive(object value)
    {
        var type = value.GetType();
        return type.IsPrimitive || type.IsEnum
            || value is decimal or DateTime or DateTimeOffset or TimeSpan or Guid;
    }

    private static JsonElement ToJson(object value)
    {
        JsonElement? serialized = null;
        try
        {
            serialized = JsonSerializer.SerializeToElement(value, value.GetType(), AIJsonUtilities.DefaultOptions);
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

    private readonly record struct Found(int Start, int Length, string EntityType, string DetectorId, bool ToolRestorable);
}
