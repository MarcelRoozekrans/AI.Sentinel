using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Screening;

/// <summary>
/// One masked occurrence in a screened text. Only spans that were actually replaced are listed: where two reports
/// overlap, the one that did not mask is left out. The value itself is not kept.
/// </summary>
/// <param name="Detector">The redacting detector credited with the span.</param>
/// <param name="EntityType">The entity type, such as <c>PHONE</c> or <c>DATE_OF_BIRTH</c>.</param>
/// <param name="Start">Zero-based start offset in the <b>input</b> text.</param>
/// <param name="Length">Length of the masked span in the input text.</param>
/// <param name="Placeholder">The string that replaced the span in the masked text: the formatter's output when
/// <see cref="ScreeningOptions.Placeholder"/> is set, otherwise the library token.</param>
public sealed record RedactionFinding(DetectorId Detector, string EntityType, int Start, int Length, string Placeholder)
{
    /// <summary>The severity the detector gave the span, or <see langword="null"/> when it gave none.</summary>
    public Severity? Severity { get; init; }
}
