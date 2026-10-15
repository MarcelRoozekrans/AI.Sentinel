using System.Text.RegularExpressions;

namespace AI.Sentinel.Detection;

/// <summary>Shared helpers for <see cref="IRedactingDetector"/> implementations built from per-type regexes.</summary>
internal static class RedactionSpanCollector
{
    // Keyword-prefixed patterns name their value group, so the span excludes the keyword.
    internal static void Collect(Regex pattern, string entityType, string text, List<RedactionSpan> spans)
    {
        foreach (Match m in pattern.Matches(text))
        {
            var g = m.Groups["value"];
            var target = g.Success ? g : m;
            spans.Add(new RedactionSpan(target.Index, target.Length, entityType));
        }
    }

    // Keeps only outermost spans. For equal ranges the earlier list entry wins,
    // so callers pass spans in priority order.
    internal static List<RedactionSpan> DropContained(List<RedactionSpan> spans)
    {
        var result = new List<RedactionSpan>(spans.Count);
        for (var i = 0; i < spans.Count; i++)
        {
            var inner = spans[i];
            var contained = false;
            for (var j = 0; j < spans.Count && !contained; j++)
            {
                var outer = spans[j];
                contained = j != i
                    && outer.Start <= inner.Start
                    && outer.Start + outer.Length >= inner.Start + inner.Length
                    && (outer.Length > inner.Length || j < i);
            }
            if (!contained) result.Add(inner);
        }
        return result;
    }

    /// <summary>Drops contained spans and sorts by Start ascending, longer first on equal starts.</summary>
    internal static List<RedactionSpan> Normalize(List<RedactionSpan> spans)
    {
        var kept = DropContained(spans);
        kept.Sort(static (a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : b.Length.CompareTo(a.Length));
        return kept;
    }
}
