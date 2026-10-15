namespace AI.Sentinel.Detection;

/// <summary>A detector that can report where in the text its matches are, so they can be redacted.</summary>
public interface IRedactingDetector : IDetector
{
    /// <summary>
    /// Returns the spans of <paramref name="text"/> this detector would flag, sorted by <c>Start</c>
    /// ascending (longer span first on equal starts), with no span contained in another.
    /// </summary>
    IReadOnlyList<RedactionSpan> FindSpans(string text);

    /// <summary>
    /// Whether the values this detector redacts may be restored into the arguments of a tool call the model
    /// makes. They are always restored into the reply the caller reads. Defaults to true. A detector of secrets
    /// returns false: a prompt-injected model could otherwise send a secret to a tool of its choice just by
    /// naming its easily guessed placeholder, so the tool receives the placeholder instead.
    /// </summary>
    bool RestoreIntoToolArguments => true;
}
