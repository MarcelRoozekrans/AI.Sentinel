using System.Text.RegularExpressions;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>Shared helpers for <see cref="IRedactingDetector"/> implementations built from per-type regexes.</summary>
internal static class RedactionSpanCollector
{
    // Keyword-prefixed patterns name their value group, so the span excludes the keyword. Spans over the
    // current call's own placeholders are dropped by the redaction session, which knows which it minted.
    internal static void Collect(Regex pattern, string entityType, string text, List<RedactionSpan> spans,
        Severity? severity = null)
    {
        foreach (Match m in pattern.Matches(text))
        {
            var target = Target(m);
            spans.Add(new RedactionSpan(target.Index, target.Length, entityType) { Severity = severity });
        }
    }

    /// <summary>
    /// True when <paramref name="pattern"/> matches <paramref name="text"/> with a value that is not one of
    /// <paramref name="placeholders"/>: `api_key=[API_KEY_1_k3f9x2]` is what a redacted request looks like, and
    /// flagging it would block the very text redaction produced. Only the placeholders in
    /// <paramref name="placeholders"/> are exempt, so a real secret shaped like one still matches.
    /// </summary>
    internal static bool HasMatch(Regex pattern, string text, IReadOnlySet<string> placeholders)
    {
        foreach (Match m in pattern.Matches(text))
        {
            var target = Target(m);
            if (PlaceholderAt(text, target.Index, target.Length) is not { } token || !placeholders.Contains(token))
            {
                return true;
            }
        }
        return false;
    }

    private static Group Target(Match m)
    {
        var g = m.Groups["value"];
        return g.Success ? g : m;
    }

    /// <summary>
    /// The placeholder, with its brackets, when the matched value is one of the form <c>[TYPE_n_tag]</c>, either
    /// including its brackets or sitting directly between them; otherwise null.
    /// </summary>
    internal static string? PlaceholderAt(string text, int index, int length)
    {
        var value = text.AsSpan(index, length);
        if (value.Length >= 2 && value[0] == '[' && value[^1] == ']')
        {
            return PlaceholderFormat.IsInner(value[1..^1]) ? value.ToString() : null;
        }

        return index > 0 && text[index - 1] == '['
            && index + length < text.Length && text[index + length] == ']'
            && PlaceholderFormat.IsInner(value)
            ? text.Substring(index - 1, length + 2)
            : null;
    }

    /// <summary>
    /// Drops every span contained in another and sorts the rest by Start ascending, longer first on equal
    /// starts. For equal ranges the earlier list entry wins, so callers pass spans in priority order.
    /// </summary>
    /// <remarks>
    /// Runs in O(k log k) for k spans: after sorting by start, then length descending, then list position, a
    /// span is contained exactly when an earlier span in that order ends at or after it. Comparing every pair
    /// instead made adversarial input with thousands of matches quadratic.
    /// </remarks>
    internal static List<RedactionSpan> Normalize(List<RedactionSpan> spans)
    {
        var order = new int[spans.Count];
        for (var i = 0; i < order.Length; i++)
        {
            order[i] = i;
        }

        Array.Sort(order, (a, b) =>
        {
            var x = spans[a];
            var y = spans[b];
            if (x.Start != y.Start) return x.Start.CompareTo(y.Start);
            if (x.Length != y.Length) return y.Length.CompareTo(x.Length);
            return a.CompareTo(b);
        });

        var kept = new List<RedactionSpan>(spans.Count);
        var maxEnd = int.MinValue;
        foreach (var index in order)
        {
            var span = spans[index];
            var end = span.Start + span.Length;
            if (end > maxEnd)
            {
                kept.Add(span);
                maxEnd = end;
            }
        }
        return kept;
    }
}
