using System.Text.RegularExpressions;

namespace AI.Sentinel.Detection;

/// <summary>Shared helpers for <see cref="IRedactingDetector"/> implementations built from per-type regexes.</summary>
internal static class RedactionSpanCollector
{
    // Keyword-prefixed patterns name their value group, so the span excludes the keyword.
    // A value that is a redaction placeholder is not a match: `api_key=[API_KEY_1]` is what a redacted
    // request looks like, and flagging it would block or re-redact the very text redaction produced.
    internal static void Collect(Regex pattern, string entityType, string text, List<RedactionSpan> spans)
    {
        foreach (Match m in pattern.Matches(text))
        {
            var target = Target(m);
            if (!IsPlaceholder(text, target.Index, target.Length))
            {
                spans.Add(new RedactionSpan(target.Index, target.Length, entityType));
            }
        }
    }

    /// <summary>True when <paramref name="pattern"/> matches <paramref name="text"/> with a value that is not a placeholder.</summary>
    internal static bool HasMatch(Regex pattern, string text)
    {
        foreach (Match m in pattern.Matches(text))
        {
            var target = Target(m);
            if (!IsPlaceholder(text, target.Index, target.Length))
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
    /// True when the matched value is a placeholder of the form <c>[TYPE_n]</c>, either including its
    /// brackets or sitting directly between them.
    /// </summary>
    internal static bool IsPlaceholder(string text, int index, int length)
    {
        var value = text.AsSpan(index, length);
        if (value.Length >= 2 && value[0] == '[' && value[^1] == ']')
        {
            return IsToken(value[1..^1]);
        }

        return index > 0 && text[index - 1] == '['
            && index + length < text.Length && text[index + length] == ']'
            && IsToken(value);
    }

    // TYPE_n: upper-case letters, digits and underscores, then an underscore and digits.
    private static bool IsToken(ReadOnlySpan<char> s)
    {
        var underscore = s.LastIndexOf('_');
        if (underscore <= 0 || underscore == s.Length - 1)
        {
            return false;
        }

        for (var i = 0; i < underscore; i++)
        {
            if (s[i] is not ((>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_'))
            {
                return false;
            }
        }

        for (var i = underscore + 1; i < s.Length; i++)
        {
            if (s[i] is < '0' or > '9')
            {
                return false;
            }
        }
        return true;
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
