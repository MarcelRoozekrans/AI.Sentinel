using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Screening;

/// <summary>The result of <see cref="SentinelPipeline.ScreenAsync"/>. A verdict is a value, never an exception.</summary>
public abstract record ScreeningOutcome
{
    /// <summary>Closes the hierarchy: only the nested cases derive from it, so a new case is an additive change.</summary>
    private protected ScreeningOutcome() { }

    /// <summary>The text was scanned and may move on.</summary>
    /// <param name="Action">The most restrictive effective action of the detections: PassThrough, Log or Alert.</param>
    /// <param name="RedactedText">The input with every redacted value replaced by its placeholder.</param>
    /// <param name="Detections">Every non-clean detection of the scan; empty for a clean text.</param>
    /// <param name="Redactions">Every masked occurrence, in input order.</param>
    /// <param name="Session">The session the audit entries were written for.</param>
    public sealed record Passed(
        SentinelAction Action,
        string RedactedText,
        IReadOnlyList<DetectionResult> Detections,
        IReadOnlyList<RedactionFinding> Redactions,
        SessionId Session) : ScreeningOutcome;

    /// <summary>The scan quarantined the text. <see cref="RedactedText"/> is still masked.</summary>
    /// <param name="Action">Always <see cref="SentinelAction.Quarantine"/>.</param>
    /// <param name="RedactedText">The input with every redacted value replaced by its placeholder.</param>
    /// <param name="Detections">Every non-clean detection of the scan.</param>
    /// <param name="Redactions">Every masked occurrence, in input order.</param>
    /// <param name="Session">The session the audit entries were written for.</param>
    public sealed record Quarantined(
        SentinelAction Action,
        string RedactedText,
        IReadOnlyList<DetectionResult> Detections,
        IReadOnlyList<RedactionFinding> Redactions,
        SessionId Session) : ScreeningOutcome;

    /// <summary>The rate limit refused the call; nothing was masked or scanned.</summary>
    /// <param name="SessionKey">The rate-limit key that ran out: the caller's session, or <c>__global__</c>.</param>
    public sealed record RateLimited(string SessionKey) : ScreeningOutcome;

    /// <summary>The pipeline itself failed, including a failed redaction. Never used for cancellation.</summary>
    /// <param name="Message">A description of the failure; it never holds the screened text.</param>
    /// <param name="Inner">The underlying exception, if one may be kept; a redaction failure keeps none, because its
    /// message can carry the value.</param>
    public sealed record Failed(string Message, Exception? Inner = null) : ScreeningOutcome;
}
