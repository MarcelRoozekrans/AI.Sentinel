using System.Text.Json;

namespace AI.Sentinel.AspNetCore.Events;

/// <summary>Writes the read answers without reflection.</summary>
internal static class EventWriter
{
    public static byte[] Write(IReadOnlyList<ShownEvent> events, IReadOnlyList<ShownGap>? gaps)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteStartArray("events");
            foreach (var (e, shownNode, name) in events)
            {
                w.WriteStartObject();
                w.WriteString("event_id", e.Id);
                w.WriteString("at", e.At);
                if (name)
                {
                    w.WriteString("developer", e.Developer);
                }

                w.WriteString("visibility", e.Visibility);
                w.WriteString("tool_kind", e.ToolKind);
                w.WriteString("outcome", e.Outcome);
                w.WriteStartArray("policies");
                foreach (var p in e.Policies)
                {
                    w.WriteStringValue(p);
                }

                w.WriteEndArray();
                Optional(w, "policy_version", e.PolicyVersion);
                Optional(w, "decided", e.DecidedAt);
                Optional(w, "node", shownNode);
                Optional(w, "cli", e.Cli);
                Optional(w, "session", e.Session);
                Optional(w, "detector", e.Detector);
                Optional(w, "severity", e.Severity);
                w.WriteStartObject("redactions");
                foreach (var (kind, count) in e.Redactions)
                {
                    w.WriteNumber(kind, count);
                }

                w.WriteEndObject();
                Optional(w, "reason", e.Reason);
                w.WriteEndObject();
            }

            w.WriteEndArray();
            if (gaps is not null)
            {
                WriteGaps(w, gaps);
            }

            w.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void Optional(Utf8JsonWriter w, string name, string? value)
    {
        if (value is not null)
        {
            w.WriteString(name, value);
        }
    }

    private static void WriteGaps(Utf8JsonWriter w, IReadOnlyList<ShownGap> gaps)
    {
        w.WriteStartArray("gaps");
        foreach (var (g, node, name) in gaps)
        {
            w.WriteStartObject();
            if (name)
            {
                w.WriteString("developer", g.Developer);
            }

            Optional(w, "node", node);
            w.WriteNumber("pruned", g.Pruned);
            w.WriteString("received_at", g.ReceivedAt);
            w.WriteEndObject();
        }

        w.WriteEndArray();
    }
}
