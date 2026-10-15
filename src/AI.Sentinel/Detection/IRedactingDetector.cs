namespace AI.Sentinel.Detection;

/// <summary>A detector that can report where in the text its matches are, so they can be redacted.</summary>
public interface IRedactingDetector : IDetector
{
    /// <summary>
    /// Returns the spans of <paramref name="text"/> this detector would flag, sorted by <c>Start</c>
    /// ascending (longer span first on equal starts), with no span contained in another.
    /// </summary>
    IReadOnlyList<RedactionSpan> FindSpans(string text);
}
