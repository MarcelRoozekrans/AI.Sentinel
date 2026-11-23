using System.Globalization;
using System.Text.Json;

namespace AI.Sentinel.AspNetCore.Events;

/// <summary>The ingest contract (ADR-240), read without reflection. A batch is
/// <c>{"organisation": "...", "events": [...], "gap": {"pruned": 3, "node": "..."}}</c>. An event holds only these fields:
/// <c>event_id</c>, <c>at</c>, <c>tool_kind</c>, <c>outcome</c>, <c>policies</c>, <c>policy_version</c>, <c>decided</c> (where it was
/// decided), <c>node</c>, <c>cli</c>, <c>session</c>, <c>detector</c>, <c>severity</c>, <c>redactions</c> (kind to count) and
/// <c>reason</c>. Any other field is dropped with its value; only its name is counted.</summary>
internal static class EventBatchReader
{
    internal const int MaxText = 256;
    internal const int MaxReason = 2000;
    internal const int MaxItems = 32;
    internal const int MaxEvents = 1000;

    /// <summary>Reads a batch, or returns <see langword="null"/> when it is not a batch.</summary>
    public static ParsedBatch? Read(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        string? organisation = null;
        var events = new List<ParsedEvent>();
        var dropped = new Dictionary<string, int>(StringComparer.Ordinal);
        var rejected = 0;
        int? pruned = null;
        string? gapNode = null;
        foreach (var property in root.EnumerateObject())
        {
            if (string.Equals(property.Name, "organisation", StringComparison.Ordinal) && property.Value.ValueKind == JsonValueKind.String)
            {
                organisation = property.Value.GetString();
            }
            else if (string.Equals(property.Name, "events", StringComparison.Ordinal) && property.Value.ValueKind == JsonValueKind.Array)
            {
                if (property.Value.GetArrayLength() > MaxEvents)
                {
                    return null;
                }

                foreach (var item in property.Value.EnumerateArray())
                {
                    if (ReadEvent(item, dropped) is { } parsed)
                    {
                        events.Add(parsed);
                    }
                    else
                    {
                        rejected++;
                    }
                }
            }
            else if (string.Equals(property.Name, "gap", StringComparison.Ordinal) && property.Value.ValueKind == JsonValueKind.Object)
            {
                (pruned, gapNode) = ReadGap(property.Value);
            }
            else
            {
                Count(dropped, property.Name);
            }
        }

        return string.IsNullOrWhiteSpace(organisation) ? null : new ParsedBatch(organisation, events, dropped, rejected, pruned, gapNode);
    }

    private static (int? Pruned, string? Node) ReadGap(JsonElement gap)
    {
        int? pruned = null;
        string? node = null;
        foreach (var property in gap.EnumerateObject())
        {
            if (string.Equals(property.Name, "pruned", StringComparison.Ordinal) && property.Value.TryGetInt32(out var n) && n > 0)
            {
                pruned = n;
            }
            else if (string.Equals(property.Name, "node", StringComparison.Ordinal))
            {
                node = Text(property.Value);
            }
        }

        return (pruned, node);
    }

    /// <summary>Each allowlisted field and how its value is read into the event. A reader returns <see langword="false"/> for a
    /// value of the wrong shape, which rejects the whole event.</summary>
    private static readonly Dictionary<string, Func<ParsedEvent, JsonElement, bool>> Fields = new(StringComparer.Ordinal)
    {
        ["event_id"] = (f, v) => (f.Id = Text(v)) is not null,
        ["at"] = (f, v) => (f.At = Time(v)) is not null,
        ["tool_kind"] = (f, v) => (f.ToolKind = Text(v)) is not null,
        ["outcome"] = (f, v) => (f.Outcome = Text(v)?.ToLowerInvariant()) is not null,
        ["policies"] = (f, v) => (f.Policies = Texts(v)) is not null,
        ["policy_version"] = (f, v) => (f.PolicyVersion = Text(v)) is not null,
        ["decided"] = (f, v) => (f.Decided = Text(v)) is not null,
        ["node"] = (f, v) => (f.Node = Text(v)) is not null,
        ["cli"] = (f, v) => (f.Cli = Text(v)) is not null,
        ["session"] = (f, v) => (f.Session = Text(v)) is not null,
        ["detector"] = (f, v) => (f.Detector = Text(v)) is not null,
        ["severity"] = (f, v) => (f.Severity = Text(v)) is not null,
        ["redactions"] = (f, v) => Counts(v) is { } counts && (f.Redactions = counts) is not null,
        ["reason"] = (f, v) => (f.Reason = v.ValueKind == JsonValueKind.String && v.GetString() is { Length: <= MaxReason } r ? r : null) is not null,
    };

    private static ParsedEvent? ReadEvent(JsonElement element, Dictionary<string, int> dropped)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var parsed = new ParsedEvent();
        var unknown = new List<string>();
        foreach (var property in element.EnumerateObject())
        {
            if (!Fields.TryGetValue(property.Name, out var read))
            {
                unknown.Add(property.Name);
            }
            else if (!read(parsed, property.Value))
            {
                return null;
            }
        }

        if (parsed.Id is null || parsed.ToolKind is null || parsed.Outcome is null)
        {
            return null;
        }

        foreach (var name in unknown)
        {
            Count(dropped, name);
        }

        return parsed;
    }

    private static void Count(Dictionary<string, int> dropped, string name)
    {
        var key = name.Length > 64 ? name[..64] : name;
        dropped[key] = dropped.GetValueOrDefault(key) + 1;
    }

    private static string? Text(JsonElement value) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 and <= MaxText } text ? text : null;

    private static DateTimeOffset? Time(JsonElement value) =>
        value.ValueKind == JsonValueKind.String
        && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at)
            ? at.ToUniversalTime()
            : null;

    private static List<string>? Texts(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > MaxItems)
        {
            return null;
        }

        var list = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (Text(item) is not { } text)
            {
                return null;
            }

            list.Add(text);
        }

        return list;
    }

    private static Dictionary<string, int>? Counts(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (counts.Count >= MaxItems || property.Name.Length > 64 || !property.Value.TryGetInt32(out var n) || n < 0)
            {
                return null;
            }

            counts[property.Name] = n;
        }

        return counts;
    }
}
