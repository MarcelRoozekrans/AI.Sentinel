using AI.Sentinel.Detection;

namespace AI.Sentinel.Redaction;

/// <summary>
/// One value a <see cref="RedactionSession"/> replaced: where it sat in the input, who reported it and the
/// placeholder that now stands for it. Overlapping reports are merged, so this is the union span, typed and
/// credited to the longest original. The value itself is not kept; <see cref="ToString"/> prints the token only.
/// </summary>
/// <param name="Start">Zero-based start offset in the input.</param>
/// <param name="Length">Length of the replaced span in the input.</param>
/// <param name="DetectorId">The detector credited with the span.</param>
/// <param name="EntityType">The normalized entity type the placeholder carries.</param>
/// <param name="Severity">The severity the credited detector assigned to the span, or null when it gave none.</param>
/// <param name="Token">The placeholder that replaced the span in the output.</param>
internal readonly record struct ReplacedSpan(
    int Start, int Length, string DetectorId, string EntityType, Severity? Severity, string Token)
{
    /// <summary>The placeholder only; the replaced value is never printed.</summary>
    public override string ToString() => Token;
}
