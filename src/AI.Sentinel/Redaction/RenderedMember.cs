namespace AI.Sentinel.Redaction;

/// <summary>
/// A member rendered as <c>"name": "value"</c>, and where in <see cref="Text"/> the value is. Never prints the text.
/// </summary>
/// <param name="text">The rendered member.</param>
/// <param name="valueStart">The offset in <paramref name="text"/> of the value's first character, after its quote.</param>
/// <param name="valueEnd">The offset in <paramref name="text"/> just past the value, at its closing quote.</param>
/// <param name="escapes">The offsets of the backslashes the rendering added to the value, ascending; null when
/// it added none.</param>
internal sealed class RenderedMember(string text, int valueStart, int valueEnd, IReadOnlyList<int>? escapes)
{
    /// <summary>The rendered member.</summary>
    public string Text { get; } = text;

    private int ValueStart { get; } = valueStart;

    private int ValueEnd { get; } = valueEnd;

    private IReadOnlyList<int>? Escapes { get; } = escapes;

    /// <summary>Never prints the member.</summary>
    public override string ToString() => nameof(RenderedMember);

    /// <summary>
    /// Maps the part of the span <c>[start, end)</c> of <see cref="Text"/> that lies in the value onto the value as
    /// it is, <c>[from, to)</c>: offsets past the escapes the rendering added. False when no part of the span lies in the value, such as
    /// a span over the name only.
    /// </summary>
    public bool TryMapToValue(int start, int end, out int from, out int to)
    {
        start = Math.Max(start, ValueStart);
        end = Math.Min(end, ValueEnd);
        if (start >= end)
        {
            from = to = 0;
            return false;
        }

        // An added backslash maps to the character it escapes, so a span starting or ending on one covers it.
        from = ToValue(start);
        to = ToValue(end - 1) + 1;
        return true;
    }

    private int ToValue(int offset) => offset - ValueStart - EscapesBefore(offset);

    private int EscapesBefore(int offset)
    {
        if (Escapes is null)
        {
            return 0;
        }

        // The number of added backslashes at offsets below offset; they are ascending.
        int lo = 0, hi = Escapes.Count;
        while (lo < hi)
        {
            var mid = (lo + hi) >>> 1;
            if (Escapes[mid] < offset)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }
        return lo;
    }
}
