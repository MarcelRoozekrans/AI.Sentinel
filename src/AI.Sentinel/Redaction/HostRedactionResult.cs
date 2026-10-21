namespace AI.Sentinel.Redaction;

/// <summary>The outcome of <see cref="SentinelPipeline.RedactAndScanAsync"/>.</summary>
/// <param name="Content">The content to send on, in the request's count and order: redacted, or the input as it was
/// when nothing redacts or the redaction fell back.</param>
/// <param name="Findings">Every detection of the scan with its effective action.</param>
/// <param name="Error">The scan's error, as <see cref="SentinelPipeline.ScanMessagesAsync"/> reports it.</param>
/// <param name="RedactedByType">Entity type to number of redacted occurrences in the content. Counts only.</param>
/// <param name="Minted">The placeholders the content redaction minted, for a host that restores them later.</param>
/// <param name="FellBack">True when the redaction failed and the content was scanned unredacted instead.</param>
internal sealed record HostRedactionResult(
    IReadOnlyList<HostContent> Content,
    IReadOnlyList<ScanFinding> Findings,
    SentinelError? Error,
    IReadOnlyDictionary<string, int> RedactedByType,
    IReadOnlyList<MintedPlaceholder> Minted,
    bool FellBack)
{
    /// <summary>True when anything in the content was redacted.</summary>
    public bool Redacted => RedactedByType.Count > 0;
}
