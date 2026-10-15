using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
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
#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _gate = new();
#else
    private readonly object _gate = new();
#endif
    private readonly Dictionary<(string Type, string Value), string> _tokenByValue = new();
    private readonly Dictionary<string, string> _valueByToken = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _nextByType = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, int>> _counts = new(StringComparer.Ordinal);

    [GeneratedRegex(@"\[(?<type>[A-Z_]+)_(?<n>\d+)\]", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
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

    public string Redact(string text)
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
                found.Add(new Found(span.Start, span.Length, span.EntityType, id));
            }
        }

        lock (_gate)
        {
            ReserveExistingPlaceholders(text);
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
            i++;
            // Partial overlaps and containment merge into one union span typed by the longest original.
            while (i < found.Count && found[i].Start < end)
            {
                var next = found[i];
                if (next.Length > winner.Length)
                {
                    winner = next;
                }
                end = Math.Max(end, next.Start + next.Length);
                i++;
            }

            sb.Append(text, pos, start - pos);
            sb.Append(TokenFor(winner.EntityType, text.Substring(start, end - start)));
            pos = end;
            Count(winner.DetectorId, winner.EntityType);
        }
        sb.Append(text, pos, text.Length - pos);
        return sb.ToString();
    }

    public IReadOnlyList<ChatMessage> Redact(IReadOnlyList<ChatMessage> messages)
    {
        var result = new List<ChatMessage>(messages.Count);
        foreach (var message in messages)
        {
            result.Add(MapMessage(message, Redact, redactResults: true));
        }
        return result;
    }

    public object? RedactResult(object? result) => MapValue(result, Redact);

    public string Restore(string text)
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
                return _valueByToken.TryGetValue(m.Value, out var original) ? original : m.Value;
            }
        });
    }

    public IList<ChatMessage> Restore(IList<ChatMessage> messages)
    {
        var result = new List<ChatMessage>(messages.Count);
        foreach (var message in messages)
        {
            result.Add(MapMessage(message, Restore, redactResults: false));
        }
        return result;
    }

    public AIFunctionArguments Restore(AIFunctionArguments args)
    {
        var restored = new AIFunctionArguments(StringComparer.Ordinal)
        {
            Context = args.Context,
            Services = args.Services,
        };
        foreach (var (key, value) in args)
        {
            restored[key] = MapValue(value, Restore);
        }
        return restored;
    }

    private string TokenFor(string type, string value)
    {
        if (_tokenByValue.TryGetValue((type, value), out var existing))
        {
            return existing;
        }

        _nextByType.TryGetValue(type, out var n);
        n = Math.Max(n, 1);
        _nextByType[type] = n + 1;
        var token = $"[{type.ToUpperInvariant()}_{n.ToString(CultureInfo.InvariantCulture)}]";
        _tokenByValue[(type, value)] = token;
        _valueByToken[token] = value;
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
            if (!int.TryParse(m.Groups["n"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n == int.MaxValue)
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

    private static ChatMessage MapMessage(ChatMessage message, Func<string, string> map, bool redactResults)
    {
        var copy = message.Clone();
        var contents = new List<AIContent>(message.Contents.Count);
        foreach (var content in message.Contents)
        {
            contents.Add(MapContent(content, map, redactResults));
        }
        copy.Contents = contents;
        return copy;
    }

    private static AIContent MapContent(AIContent content, Func<string, string> map, bool redactResults)
    {
        switch (content)
        {
            case TextContent text:
                return CopyMetadata(text, new TextContent(text.Text is null ? null : map(text.Text)));
            case FunctionCallContent call:
                IDictionary<string, object?>? args = null;
                if (call.Arguments is not null)
                {
                    var mapped = new Dictionary<string, object?>(call.Arguments.Count, StringComparer.Ordinal);
                    foreach (var (key, value) in call.Arguments)
                    {
                        mapped[key] = MapValue(value, map);
                    }
                    args = mapped;
                }
                var callCopy = new FunctionCallContent(call.CallId, call.Name, args)
                {
                    Exception = call.Exception,
                    InformationalOnly = call.InformationalOnly,
                };
                return CopyMetadata(call, callCopy);
            case FunctionResultContent fr when redactResults:
                var resultCopy = new FunctionResultContent(fr.CallId, MapValue(fr.Result, map))
                {
                    Exception = fr.Exception,
                };
                return CopyMetadata(fr, resultCopy);
            default:
                return content;
        }
    }

    private static T CopyMetadata<T>(AIContent source, T target) where T : AIContent
    {
        target.AdditionalProperties = source.AdditionalProperties;
        target.Annotations = source.Annotations;
        target.RawRepresentation = source.RawRepresentation;
        return target;
    }

    private static object? MapValue(object? value, Func<string, string> map) => value switch
    {
        string s => map(s),
        JsonElement e => MapJson(e, map),
        _ => value,
    };

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
                    writer.WritePropertyName(property.Name);
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

    private readonly record struct Found(int Start, int Length, string EntityType, string DetectorId);
}
